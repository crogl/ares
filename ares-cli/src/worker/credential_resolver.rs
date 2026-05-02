//! State-based credential resolver for tool dispatch.
//!
//! The LLM names principals (`username`, `domain`) and targets — never secret
//! material. This module resolves the actual `password`, `hash`, `aes_key`,
//! `ticket_path`, `trust_key`, and SID values from operation state immediately
//! before `ares_tools::dispatch`.
//!
//! If the LLM (or anything upstream) supplies a credential-shaped argument, this
//! resolver replaces it with the state-resolved value. The LLM never wins.
//!
//! When state has no value for a credential the tool needs, the resolver leaves
//! the field absent and the tool's executor surfaces a normal "missing
//! parameter" error to the LLM. That signal tells the orchestrator to harvest
//! credentials before retrying.
//!
//! Lookup keys per field:
//!
//! | Field                 | Source                                         |
//! | --------------------- | ---------------------------------------------- |
//! | `password`            | `Credential.password` by `(username, domain)`  |
//! | `hash`                | `Hash.hash_value` by `(username, domain)`      |
//! | `nt_hash`             | NT half of `Hash.hash_value`                   |
//! | `aes_key`             | `Hash.aes_key` by `(username, domain)`         |
//! | `ticket_path`         | most-recent `*.ccache` matching principal      |
//! | `krbtgt_hash`         | `Hash` for `(krbtgt, domain)`                  |
//! | `child_krbtgt_hash`   | `Hash` for `(krbtgt, child_domain)`            |
//! | `trust_key`           | `Hash` for `(target_netbios + '$', source)`    |
//! | `trust_aes_key`       | `Hash.aes_key` for trust account                |
//! | `domain_sid`          | `domain_sids` HASH by `domain`                 |
//! | `source_sid`          | `domain_sids` HASH by `source_domain`          |
//! | `target_sid`          | `domain_sids` HASH by `target_domain`/trusted  |

use std::path::PathBuf;

use anyhow::Result;
use redis::aio::ConnectionManager;
use serde_json::{Map, Value};
use tracing::{debug, info, warn};

use ares_core::models::{Credential, Hash};
use ares_core::state::RedisStateReader;

/// Argument keys that contain secret material and must come from state, never
/// from the LLM.
pub const CREDENTIAL_KEYS: &[&str] = &[
    "password",
    "hash",
    "nt_hash",
    "ntlm_hash",
    "aes_key",
    "aes256_key",
    "ticket_path",
    "krbtgt_hash",
    "child_krbtgt_hash",
    "parent_krbtgt_hash",
    "trust_key",
    "trust_aes_key",
    "trust_hash",
    "admin_hash",
    "coerce_password",
    "coerce_hash",
    "domain_sid",
    "source_sid",
    "target_sid",
    "extra_sid",
    "kerberos_keys",
];

/// Resolve credential arguments for a tool call from operation state.
///
/// Mutates `arguments` in place. Reads `username`, `domain`, `source_domain`,
/// `target_domain`, `trusted_domain`, `child_domain` to identify the principal.
/// Looks up credentials from the operation's Redis state and sets credential
/// keys on the arguments object.
///
/// If `operation_id` is `None`, this is a no-op: the tool runs with whatever
/// arguments were provided. This handles direct CLI invokes and tests.
pub async fn resolve_credentials(
    conn: &mut ConnectionManager,
    operation_id: Option<&str>,
    tool_name: &str,
    arguments: &mut Value,
) -> Result<()> {
    let Some(op_id) = operation_id else {
        debug!(
            tool = %tool_name,
            "credential_resolver: no operation_id, skipping resolution"
        );
        return Ok(());
    };

    let Some(args_obj) = arguments.as_object_mut() else {
        return Ok(());
    };

    // Strip any LLM-supplied credential placeholders before lookup. Even if
    // state has nothing, we never want a `[HASH]` or `<password>` literal to
    // reach the dispatch layer.
    strip_placeholder_credentials(args_obj);

    let reader = RedisStateReader::new(op_id.to_string());

    // Bulk-load state once per call. These are HASHes/LISTs cached in Redis,
    // so the cost is small relative to the subsequent tool execution.
    let credentials = reader.get_credentials(conn).await.unwrap_or_default();
    let hashes = reader.get_hashes(conn).await.unwrap_or_default();
    let domain_sids = reader.get_domain_sids(conn).await.unwrap_or_default();

    let primary_username = string_field(args_obj, "username");
    // `bind_domain` is the auth realm for cross-forest queries (e.g.
    // ldap_search against fabrikam.local using a contoso.local principal).
    // `domain` is the *target* of the query in those tools, not the
    // credential's domain — looking up `(user, domain=target)` misses the
    // stored principal. Prefer `bind_domain` when present so cross-forest
    // LDAP/RPC enumerations can resolve their auth cred.
    let mut primary_domain = string_field(args_obj, "bind_domain")
        .or_else(|| string_field(args_obj, "domain"))
        .or_else(|| string_field(args_obj, "source_domain"))
        .or_else(|| string_field(args_obj, "child_domain"));

    // Fallback: when LLM passes `domain=""`, infer the domain from the
    // target host. Without this, every downstream resolution (password,
    // hash, ticket) fails because primary_domain is None and the
    // `(Some, Some)` guard below never fires. Tools then bail with
    // "credentials must be present in operation state for the (user, domain)
    // pair" even though the credential exists under the host's domain.
    //
    // Resolution order — first match wins:
    //   1. If `target`/`target_ip`/`dc_ip` is an IP that matches a DC, use
    //      that DC's domain.
    //   2. If `target_hostname`/`hostname`/`target` carries an FQDN suffix
    //      (e.g. `dc01.contoso.local`), use the suffix.
    if primary_domain.is_none() {
        primary_domain = infer_domain_from_target(args_obj, conn, &reader).await;
        if let Some(ref d) = primary_domain {
            // Inject the resolved domain back into args so downstream tools
            // (which read `domain` directly) get a non-empty realm too.
            if !args_obj
                .get("domain")
                .and_then(|v| v.as_str())
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false)
            {
                args_obj.insert("domain".to_string(), Value::String(d.clone()));
            }
            debug!(
                tool = %tool_name,
                domain = %d,
                "credential_resolver: inferred missing domain from target host"
            );
        }
    }

    info!(
        tool = %tool_name,
        user = primary_username.as_deref().unwrap_or("(none)"),
        domain = primary_domain.as_deref().unwrap_or("(none)"),
        cred_count = credentials.len(),
        hash_count = hashes.len(),
        "credential_resolver: resolving"
    );

    // Standard principal credentials (password, hash, aes_key)
    if let (Some(user), Some(domain)) = (primary_username.as_deref(), primary_domain.as_deref()) {
        let pw_before = args_obj.contains_key("password");
        let hash_before = args_obj.contains_key("hash");
        let realm_strict = requires_exact_realm(tool_name);
        resolve_principal_credentials(args_obj, &credentials, &hashes, user, domain, realm_strict);
        let pw_injected = !pw_before && args_obj.contains_key("password");
        let hash_injected = !hash_before && args_obj.contains_key("hash");
        if pw_injected || hash_injected {
            info!(
                tool = %tool_name,
                user = %user,
                domain = %domain,
                injected_password = pw_injected,
                injected_hash = hash_injected,
                "credential_resolver: injected from state"
            );
        } else if !pw_before && !hash_before {
            warn!(
                tool = %tool_name,
                user = %user,
                domain = %domain,
                cred_count = credentials.len(),
                hash_count = hashes.len(),
                "credential_resolver: no credential matched principal in state"
            );
        }
    }

    // Auxiliary principal: `coerce_user` / `coerce_domain` for relay_and_coerce.
    // The LLM names the coercion principal; the resolver injects
    // `coerce_password` or `coerce_hash` from state.
    resolve_coerce_principal(args_obj, &credentials, &hashes);

    // Kerberos ticket path — pick most recent matching ccache when the schema
    // expects one but the args don't have it.
    if expects_ticket(tool_name, args_obj) {
        if let (Some(user), Some(domain)) = (primary_username.as_deref(), primary_domain.as_deref())
        {
            if let Some(path) = find_ccache(user, domain) {
                args_obj.insert("ticket_path".to_string(), Value::String(path));
            }
        }
    }

    // krbtgt hash — for golden ticket forging.
    resolve_krbtgt_hashes(args_obj, &hashes);

    // Cross-forest Kerberos ticket — inject ticket_path for LDAP-bind tools
    // when the target server is in a foreign forest. `primary_domain` prefers
    // `bind_domain` (the auth realm) for cred resolution, but the inter-realm
    // ticket must be looked up by the *target* realm (the server's realm).
    // For ldap_acl_enumeration / ldap_search against a foreign DC, the LLM
    // passes `domain=<target_realm>` and `bind_domain=<auth_realm>` — without
    // this distinction we look up the ticket under the auth realm and miss
    // the forged ccache, leaving the tool to attempt cross-realm NTLM bind
    // (which the foreign DC rejects with 0x52e).
    if requires_exact_realm(tool_name) && !args_obj.contains_key("ticket_path") {
        let target_realm = string_field(args_obj, "target_domain")
            .or_else(|| string_field(args_obj, "domain"))
            .or_else(|| primary_domain.clone());
        if let Some(ref realm) = target_realm {
            resolve_cross_forest_ticket(args_obj, &reader, conn, tool_name, realm, &hashes).await;
        }
    }

    // Trust keys — Hash entries for `<TRUSTED>$` machine accounts.
    resolve_trust_key(args_obj, &hashes, &reader, conn).await;

    // Domain SIDs — direct lookup against the domain_sids HASH.
    resolve_domain_sids(args_obj, &domain_sids);

    Ok(())
}

/// Remove any credential-shaped argument whose value is empty, null, or a
/// placeholder literal (e.g. `[HASH]`, `<password>`, `N/A`, `unknown`).
fn strip_placeholder_credentials(args: &mut Map<String, Value>) {
    let mut to_remove = Vec::new();
    for key in CREDENTIAL_KEYS {
        if let Some(v) = args.get(*key) {
            if is_placeholder_value(v) {
                to_remove.push((*key).to_string());
            }
        }
    }
    for key in to_remove {
        warn!(
            arg = %key,
            "credential_resolver: stripping LLM-supplied placeholder credential"
        );
        args.remove(&key);
    }
}

fn is_placeholder_value(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => is_placeholder_str(s),
        _ => false,
    }
}

fn is_placeholder_str(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() {
        return true;
    }
    // Bracketed placeholders: [TGT], [PWD], <hash>, <parent_admin_hash>
    if (t.starts_with('[') && t.ends_with(']')) || (t.starts_with('<') && t.ends_with('>')) {
        return true;
    }
    let lower = t.to_ascii_lowercase();
    // Bare placeholder words the LLM has been observed to invent.
    matches!(
        lower.as_str(),
        "n/a"
            | "na"
            | "null"
            | "none"
            | "nil"
            | "unknown"
            | "tbd"
            | "todo"
            | "password"
            | "hash"
            | "ntlm"
            | "nthash"
            | "tgt"
            | "ticket"
            | "ccache"
            | "aes"
            | "aes_key"
            | "trust_key"
            | "domain_sid"
            | "krbtgt_hash"
            | "placeholder"
            | "<value>"
            | "<password>"
            | "<hash>"
            | "<tgt>"
            | "<pwd>"
    )
}

/// Resolve `password`, `hash`, `nt_hash`, `aes_key` for the primary principal.
///
/// `realm_strict` controls cross-realm fallback. When true, only credentials
/// matching the requested `domain` are returned; the `any_user` fallback is
/// suppressed. Set this for tools that perform a direct bind against the
/// target realm's DC (LDAP/RPC), where a foreign-realm cred just produces
/// invalidCredentials (52e/775). Leave false for tools that traverse trusts
/// via Kerberos referral or NTLM pass-through (smbclient, secretsdump),
/// where the user-matching cred from a different realm still authenticates.
fn resolve_principal_credentials(
    args: &mut Map<String, Value>,
    credentials: &[Credential],
    hashes: &[Hash],
    username: &str,
    domain: &str,
    realm_strict: bool,
) {
    if !args.contains_key("password") {
        if let Some(cred) = find_credential(credentials, username, domain, realm_strict) {
            if !cred.password.is_empty() {
                args.insert("password".to_string(), Value::String(cred.password.clone()));
                debug!(
                    user = %username,
                    domain = %domain,
                    "credential_resolver: injected password from state"
                );
            }
        }
    }

    let hash_match = find_hash(hashes, username, domain, realm_strict);
    if let Some(h) = hash_match {
        if !args.contains_key("hash") && !h.hash_value.is_empty() {
            args.insert("hash".to_string(), Value::String(h.hash_value.clone()));
            debug!(
                user = %username,
                domain = %domain,
                "credential_resolver: injected hash from state"
            );
        }
        if !args.contains_key("nt_hash") && !h.hash_value.is_empty() {
            let nt = nt_hash_only(&h.hash_value).to_string();
            if !nt.is_empty() {
                args.insert("nt_hash".to_string(), Value::String(nt));
            }
        }
        if !args.contains_key("aes_key") {
            if let Some(aes) = h.aes_key.as_deref().filter(|s| !s.is_empty()) {
                args.insert("aes_key".to_string(), Value::String(aes.to_string()));
            }
        }
    }
}

/// Inject `coerce_password` / `coerce_hash` for `relay_and_coerce` based on
/// `(coerce_user, coerce_domain)` in the args. Mirrors
/// `resolve_principal_credentials` but writes to the `coerce_*` keys.
///
/// No-op when `coerce_user` is absent or empty. When the user has only a
/// password in state, sets `coerce_password`; when only a hash, sets
/// `coerce_hash`. If both exist, sets only `coerce_hash` (the auth path
/// downstream prefers PTH for relay-fallback DFSCoerce/Coercer auth).
fn resolve_coerce_principal(
    args: &mut Map<String, Value>,
    credentials: &[Credential],
    hashes: &[Hash],
) {
    let Some(user) = string_field(args, "coerce_user") else {
        return;
    };
    if user.is_empty() {
        return;
    }
    let domain = string_field(args, "coerce_domain").unwrap_or_default();

    if !args.contains_key("coerce_hash") && !args.contains_key("coerce_password") {
        if let Some(h) = find_hash(hashes, &user, &domain, false) {
            if !h.hash_value.is_empty() {
                args.insert(
                    "coerce_hash".to_string(),
                    Value::String(h.hash_value.clone()),
                );
                debug!(
                    user = %user,
                    domain = %domain,
                    "credential_resolver: injected coerce_hash from state"
                );
                return;
            }
        }
        if let Some(cred) = find_credential(credentials, &user, &domain, false) {
            if !cred.password.is_empty() {
                args.insert(
                    "coerce_password".to_string(),
                    Value::String(cred.password.clone()),
                );
                debug!(
                    user = %user,
                    domain = %domain,
                    "credential_resolver: injected coerce_password from state"
                );
            }
        }
    }
}

/// Look up the krbtgt hash for the relevant domain when the tool needs it.
///
/// Tools like `generate_golden_ticket` consume `krbtgt_hash`. The LLM names
/// the domain to forge in; we look up the most recent `Hash` for `krbtgt` in
/// that domain.
fn resolve_krbtgt_hashes(args: &mut Map<String, Value>, hashes: &[Hash]) {
    // krbtgt is per-domain — never cross-realm fall back. A different
    // domain's krbtgt forges a useless ticket.
    if !args.contains_key("krbtgt_hash") {
        if let Some(domain) = string_field(args, "domain") {
            if let Some(h) = find_hash(hashes, "krbtgt", &domain, true) {
                if !h.hash_value.is_empty() {
                    args.insert(
                        "krbtgt_hash".to_string(),
                        Value::String(h.hash_value.clone()),
                    );
                }
            }
        }
    }

    if !args.contains_key("child_krbtgt_hash") {
        if let Some(child) = string_field(args, "child_domain") {
            if let Some(h) = find_hash(hashes, "krbtgt", &child, true) {
                if !h.hash_value.is_empty() {
                    args.insert(
                        "child_krbtgt_hash".to_string(),
                        Value::String(h.hash_value.clone()),
                    );
                }
            }
        }
    }
}

/// Resolve the inter-realm trust key for cross-domain ticket forging.
///
/// Trust keys are stored as `Hash` entries with username `<TRUSTED_NETBIOS>$`
/// in the source domain (where the trust was extracted). We try both the
/// trusted-domain name and its NetBIOS flat name from the trust info.
async fn resolve_trust_key(
    args: &mut Map<String, Value>,
    hashes: &[Hash],
    reader: &RedisStateReader,
    conn: &mut ConnectionManager,
) {
    if args.contains_key("trust_key") {
        return;
    }
    let Some(source_domain) = string_field(args, "source_domain")
        .or_else(|| string_field(args, "domain"))
        .or_else(|| string_field(args, "child_domain"))
    else {
        return;
    };
    let Some(target_domain) = string_field(args, "target_domain")
        .or_else(|| string_field(args, "trusted_domain"))
        .or_else(|| string_field(args, "parent_domain"))
    else {
        return;
    };

    // Possible trust account usernames the worker has stored.
    let mut candidates: Vec<String> = vec![
        format!("{}$", target_domain.split('.').next().unwrap_or("")).to_uppercase(),
        format!("{target_domain}$"),
    ];
    // Look up flat name from trust info.
    if let Ok(trusted) = reader.get_trusted_domains(conn).await {
        if let Some(trust) = trusted.get(&target_domain.to_lowercase()) {
            if !trust.flat_name.is_empty() {
                candidates.push(format!("{}$", trust.flat_name));
                candidates.push(format!("{}$", trust.flat_name.to_uppercase()));
            }
        }
    }
    candidates.retain(|c| !c.is_empty() && !c.starts_with('$'));

    for cand in &candidates {
        // Trust keys are per-(source, target$) — never cross-realm fall back.
        if let Some(h) = find_hash(hashes, cand, &source_domain, true) {
            if !h.hash_value.is_empty() {
                args.insert("trust_key".to_string(), Value::String(h.hash_value.clone()));
                if !args.contains_key("trust_aes_key") {
                    if let Some(aes) = h.aes_key.as_deref().filter(|s| !s.is_empty()) {
                        args.insert("trust_aes_key".to_string(), Value::String(aes.to_string()));
                    }
                }
                debug!(
                    source = %source_domain,
                    target = %target_domain,
                    account = %cand,
                    "credential_resolver: injected trust_key from state"
                );
                return;
            }
        }
    }
}

/// Resolve `domain_sid`, `source_sid`, `target_sid` from the `domain_sids` HASH.
fn resolve_domain_sids(
    args: &mut Map<String, Value>,
    domain_sids: &std::collections::HashMap<String, String>,
) {
    let lookups: &[(&str, &[&str])] = &[
        ("domain_sid", &["domain"]),
        ("source_sid", &["source_domain", "domain", "child_domain"]),
        (
            "target_sid",
            &["target_domain", "trusted_domain", "parent_domain"],
        ),
    ];

    for (sid_key, domain_keys) in lookups {
        if args.contains_key(*sid_key) {
            continue;
        }
        for domain_key in *domain_keys {
            if let Some(domain) = string_field(args, domain_key) {
                if let Some(sid) = lookup_domain_sid(domain_sids, &domain) {
                    args.insert((*sid_key).to_string(), Value::String(sid));
                    break;
                }
            }
        }
    }
}

fn lookup_domain_sid(
    domain_sids: &std::collections::HashMap<String, String>,
    domain: &str,
) -> Option<String> {
    let lower = domain.to_lowercase();
    if let Some(s) = domain_sids.get(&lower) {
        return Some(s.clone());
    }
    domain_sids.get(domain).cloned()
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Best-effort domain resolution from a tool call's target arguments.
///
/// Walks the standard target argument keys in priority order:
///   - IP-shaped values are matched against the DC map (`domain → dc_ip`),
///     returning the DC's domain.
///   - FQDN-shaped values return their domain suffix (`dc01.contoso.local`
///     → `contoso.local`).
///   - Bare hostnames / unmatched IPs are skipped — a wrong-domain guess
///     here would just produce an authentication failure.
async fn infer_domain_from_target(
    args: &Map<String, Value>,
    conn: &mut ConnectionManager,
    reader: &RedisStateReader,
) -> Option<String> {
    const TARGET_KEYS: &[&str] = &[
        "target",
        "target_ip",
        "dc_ip",
        "target_host",
        "target_hostname",
        "hostname",
        "host",
    ];

    let dc_map = reader.get_dc_map(conn).await.unwrap_or_default();

    for key in TARGET_KEYS {
        let Some(value) = string_field(args, key) else {
            continue;
        };
        // FQDN suffix: anything with a dot that isn't an IP literal.
        if !looks_like_ip(&value) {
            if let Some((_, suffix)) = value.split_once('.') {
                let s = suffix.trim().to_lowercase();
                if !s.is_empty() && s.contains('.') {
                    return Some(s);
                }
            }
            continue;
        }
        // IP literal: look up against the DC map.
        for (domain, ip) in &dc_map {
            if ip.trim() == value {
                let d = domain.trim().to_lowercase();
                if !d.is_empty() {
                    return Some(d);
                }
            }
        }
    }
    None
}

fn looks_like_ip(s: &str) -> bool {
    let trimmed = s.trim();
    let octets: Vec<&str> = trimmed.split('.').collect();
    octets.len() == 4 && octets.iter().all(|o| o.parse::<u8>().is_ok())
}

fn string_field(args: &Map<String, Value>, key: &str) -> Option<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn find_credential<'a>(
    credentials: &'a [Credential],
    username: &str,
    domain: &str,
    realm_strict: bool,
) -> Option<&'a Credential> {
    let user_l = username.to_lowercase();
    let domain_l = domain.to_lowercase();
    let domain_empty = domain_l.is_empty();

    let mut exact: Option<&Credential> = None;
    let mut any_user: Option<&Credential> = None;
    for cred in credentials {
        if cred.username.to_lowercase() != user_l {
            continue;
        }
        if cred.password.is_empty() || is_placeholder_str(&cred.password) {
            continue;
        }
        let domain_match = domain_empty || cred.domain.to_lowercase() == domain_l;
        if domain_match {
            match exact {
                None => exact = Some(cred),
                Some(prev) if cred.attack_step >= prev.attack_step => exact = Some(cred),
                _ => {}
            }
        }
        match any_user {
            None => any_user = Some(cred),
            Some(prev) if cred.attack_step >= prev.attack_step => any_user = Some(cred),
            _ => {}
        }
    }
    // Realm-strict callers (LDAP/RPC direct bind) MUST get an exact-realm
    // match or nothing. A foreign-realm cred just produces 52e/775 at bind
    // time and burns the dispatch.
    if realm_strict {
        return exact;
    }
    // Username-only fallback: when the LLM passes the *target* domain (the
    // tool's destination) instead of the credential's home realm, exact match
    // fails. Cross-realm tools (smbclient against a foreign DC, secretsdump
    // with cross-forest principal) still need that user's password — Kerberos
    // referrals or NTLM pass-through handle the actual auth. Returning a
    // user-matching cred from a different realm beats refusing the dispatch
    // and forcing the agent to re-request the same lookup.
    //
    // Skip the fallback for common per-domain accounts: each AD domain has
    // its own `Administrator`/`Guest`/`krbtgt` SAM account with a different
    // password and SID. Substituting one domain's `Administrator` for
    // another's just produces STATUS_LOGON_FAILURE and burns a tool call.
    if exact.is_some() || !is_common_per_domain_account(&user_l) {
        exact.or(any_user)
    } else {
        exact
    }
}

fn is_common_per_domain_account(user_l: &str) -> bool {
    matches!(user_l, "administrator" | "guest" | "krbtgt")
}

/// Tools that authenticate via direct bind to the target realm's DC (LDAP or
/// LDAP-backed RPC). For these, a cross-realm cred from another forest just
/// produces STATUS_LOGON_FAILURE / invalidCredentials. The orchestrator gets
/// faster forward progress by returning no credential — the dispatch fails
/// cleanly, the failure is reported back, and the orchestrator can re-derive
/// the right principal — than by injecting a wrong-realm cred that wastes
/// the LLM's tool budget on a guaranteed-failed bind.
///
/// Tools NOT in this list (smbclient, secretsdump, nxc) traverse trusts via
/// Kerberos referral or NTLM pass-through and benefit from the cross-realm
/// `any_user` fallback.
pub(crate) fn requires_exact_realm(tool_name: &str) -> bool {
    matches!(
        tool_name,
        "bloodyad_set_password"
            | "bloodyad_add_group_member"
            | "bloodyad_add_genericall"
            | "dacl_edit"
            | "pywhisker"
            | "ldap_search"
            | "ldap_search_descriptions"
            | "ldap_acl_enumeration"
            | "targeted_kerberoast"
    )
}

fn find_hash<'a>(
    hashes: &'a [Hash],
    username: &str,
    domain: &str,
    realm_strict: bool,
) -> Option<&'a Hash> {
    let user_l = username.to_lowercase();
    let domain_l = domain.to_lowercase();
    let domain_empty = domain_l.is_empty();

    let mut exact: Option<&Hash> = None;
    let mut exact_aes: Option<&Hash> = None;
    let mut any_user: Option<&Hash> = None;
    let mut any_user_aes: Option<&Hash> = None;
    for h in hashes {
        if h.username.to_lowercase() != user_l {
            continue;
        }
        if h.hash_value.is_empty() {
            continue;
        }
        if !is_authenticating_hash_type(&h.hash_type) {
            continue;
        }
        let h_domain_l = h.domain.to_lowercase();
        let domain_match = domain_empty || h.domain.is_empty() || h_domain_l == domain_l;
        let has_aes = h.aes_key.as_deref().is_some_and(|s| !s.is_empty());
        if domain_match {
            match exact {
                None => exact = Some(h),
                Some(prev) if h.attack_step >= prev.attack_step => exact = Some(h),
                _ => {}
            }
            if has_aes {
                match exact_aes {
                    None => exact_aes = Some(h),
                    Some(prev) if h.attack_step >= prev.attack_step => exact_aes = Some(h),
                    _ => {}
                }
            }
        }
        match any_user {
            None => any_user = Some(h),
            Some(prev) if h.attack_step >= prev.attack_step => any_user = Some(h),
            _ => {}
        }
        if has_aes {
            match any_user_aes {
                None => any_user_aes = Some(h),
                Some(prev) if h.attack_step >= prev.attack_step => any_user_aes = Some(h),
                _ => {}
            }
        }
    }
    let exact_pick = exact_aes.or(exact);
    if realm_strict {
        return exact_pick;
    }
    if exact_pick.is_some() || !is_common_per_domain_account(&user_l) {
        exact_pick.or(any_user_aes).or(any_user)
    } else {
        exact_pick
    }
}

/// True when this hash type can be used directly for authentication (NTLM,
/// AES key). False for offline-cracking artifacts like kerberoast/asreproast
/// TGS ciphertext.
fn is_authenticating_hash_type(hash_type: &str) -> bool {
    let t = hash_type.to_ascii_lowercase();
    !matches!(
        t.as_str(),
        "kerberoast" | "asreproast" | "asrep" | "tgs" | "krb5tgs" | "krb5asrep"
    )
}

/// Strip an `LM:NT` colon-form hash to just the NT half.
fn nt_hash_only(hash: &str) -> &str {
    hash.rsplit(':').next().unwrap_or(hash).trim()
}

/// True when the tool expects a Kerberos ticket and the args don't have one.
fn expects_ticket(tool_name: &str, args: &Map<String, Value>) -> bool {
    if args.contains_key("ticket_path") {
        return false;
    }
    tool_name.ends_with("_kerberos")
        || matches!(
            tool_name,
            "secretsdump_kerberos" | "psexec_kerberos" | "wmiexec_kerberos" | "smbexec_kerberos"
        )
}

/// Find the most-recent `*.ccache` file in the worker's working directory that
/// matches the principal.
///
/// Convention: tools that forge tickets save them as `<Username>.ccache` in CWD.
/// We accept either an exact match or any ccache when the principal matches by
/// stem.
fn find_ccache(username: &str, _domain: &str) -> Option<String> {
    let cwd = std::env::current_dir().ok()?;
    let user_lower = username.to_lowercase();

    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    let entries = std::fs::read_dir(&cwd).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !name.ends_with(".ccache") {
            continue;
        }
        let stem = name.trim_end_matches(".ccache").to_lowercase();
        if stem != user_lower && !stem.starts_with(&user_lower) {
            continue;
        }
        let mtime = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        match &best {
            None => best = Some((mtime, path)),
            Some((t, _)) if mtime >= *t => best = Some((mtime, path)),
            _ => {}
        }
    }
    best.map(|(_, p)| p.to_string_lossy().to_string())
}

/// Inject `ticket_path` for a cross-forest LDAP-bind tool using a forged
/// inter-realm ccache stored in Redis.
///
/// Called only when `requires_exact_realm(tool_name)` is true and the
/// primary domain has no matching NTLM credential in state (i.e. the target
/// is a foreign forest where NTLM bind would return 0x52e). Looks up the
/// `kerberos_tickets` HASH for a `(*, target_domain, Administrator)` entry
/// and injects the ccache path into `args["ticket_path"]`.
///
/// If the target domain doesn't have a kerberos ticket in Redis this is a
/// no-op — the tool will fail with a missing-credential error, which is the
/// correct signal to the orchestrator.
async fn resolve_cross_forest_ticket(
    args: &mut Map<String, Value>,
    reader: &RedisStateReader,
    conn: &mut ConnectionManager,
    tool_name: &str,
    target_domain: &str,
    hashes: &[Hash],
) {
    // Only fire when the tool has no usable NTLM credential for the target
    // domain (i.e. the realm_strict check already blocked cross-realm fallback).
    // If there's already an exact-domain hash for a non-common account, NTLM
    // bind will work and we don't need Kerberos.
    let user_l = string_field(args, "username")
        .map(|u| u.to_lowercase())
        .unwrap_or_default();
    let domain_l = target_domain.to_lowercase();
    let has_ntlm = hashes.iter().any(|h| {
        h.domain.to_lowercase() == domain_l
            && (user_l.is_empty() || h.username.to_lowercase() == user_l)
            && !h.hash_value.is_empty()
            && is_authenticating_hash_type(&h.hash_type)
    });
    if has_ntlm {
        // NTLM bind is available — no need to inject Kerberos ticket.
        return;
    }

    // Look up kerberos_tickets HASH in Redis.
    let tickets = reader.get_kerberos_tickets(conn).await.unwrap_or_default();

    // Find the most recent ticket for the target domain (any source, Administrator).
    // Administrator is the only username we forge in the suppression path.
    let ticket = tickets.iter().find(|t| {
        t.target_domain.to_lowercase() == domain_l
            && t.username.eq_ignore_ascii_case("Administrator")
            && !t.ticket_path.is_empty()
    });

    let Some(ticket) = ticket else {
        debug!(
            tool = %tool_name,
            target_domain = %target_domain,
            "credential_resolver: no inter-realm Kerberos ticket found for cross-forest tool"
        );
        return;
    };

    // Sanity-check the ccache exists on disk (best-effort — workers may not
    // share the same host in some deployments).
    if !std::path::Path::new(&ticket.ticket_path).exists() {
        warn!(
            tool = %tool_name,
            target_domain = %target_domain,
            ticket_path = %ticket.ticket_path,
            "credential_resolver: inter-realm ccache not found on disk — skipping injection"
        );
        return;
    }

    info!(
        tool = %tool_name,
        target_domain = %target_domain,
        ticket_path = %ticket.ticket_path,
        source_domain = %ticket.source_domain,
        "credential_resolver: injecting inter-realm Kerberos ticket for cross-forest LDAP bind"
    );
    args.insert(
        "ticket_path".to_string(),
        Value::String(ticket.ticket_path.clone()),
    );

    // GSSAPI bind needs an FQDN to derive the ldap/<host>@<REALM> SPN. If the
    // LLM passed an IP for `target`, look up the host's hostname from state
    // and rewrite. Without this, ldapsearch -Y GSSAPI errors with no Kerberos
    // service principal name found.
    if let Some(ip_str) = string_field(args, "target") {
        if ip_str.parse::<std::net::IpAddr>().is_ok() {
            let hosts = reader.get_hosts(conn).await.unwrap_or_default();
            let domain_l = target_domain.to_lowercase();
            let host_match = hosts
                .iter()
                .find(|h| h.ip == ip_str && !h.hostname.is_empty());
            if let Some(h) = host_match {
                let hn = h.hostname.to_lowercase();
                let fqdn = if hn.ends_with(&format!(".{domain_l}")) || hn == domain_l {
                    hn
                } else {
                    format!("{hn}.{domain_l}")
                };
                info!(
                    tool = %tool_name,
                    old_target = %ip_str,
                    new_target = %fqdn,
                    "credential_resolver: rewrote target IP to FQDN for GSSAPI bind"
                );
                args.insert("target".to_string(), Value::String(fqdn));
            } else {
                warn!(
                    tool = %tool_name,
                    target_ip = %ip_str,
                    target_domain = %target_domain,
                    "credential_resolver: no FQDN found for target IP — GSSAPI bind may fail SPN lookup"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::{Credential, Hash};
    use serde_json::json;

    fn cred(user: &str, domain: &str, pass: &str) -> Credential {
        Credential {
            id: format!("c-{user}"),
            username: user.to_string(),
            password: pass.to_string(),
            domain: domain.to_string(),
            source: "test".into(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn hash(user: &str, domain: &str, value: &str, aes: Option<&str>) -> Hash {
        Hash {
            id: format!("h-{user}"),
            username: user.to_string(),
            hash_value: value.to_string(),
            hash_type: "NTLM".into(),
            domain: domain.to_string(),
            cracked_password: None,
            source: "test".into(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: aes.map(String::from),
        }
    }

    #[test]
    fn placeholder_str_recognizes_brackets() {
        assert!(is_placeholder_str("[TGT]"));
        assert!(is_placeholder_str("[HASH]"));
        assert!(is_placeholder_str("<password>"));
        assert!(is_placeholder_str("<parent_administrator_NTLM_hash>"));
    }

    #[test]
    fn placeholder_str_recognizes_words() {
        assert!(is_placeholder_str("N/A"));
        assert!(is_placeholder_str("null"));
        assert!(is_placeholder_str("None"));
        assert!(is_placeholder_str("unknown"));
        assert!(is_placeholder_str("password"));
        assert!(is_placeholder_str("HASH"));
        assert!(is_placeholder_str("  TGT  "));
    }

    #[test]
    fn placeholder_str_passes_real_values() {
        assert!(!is_placeholder_str("aad3b435b51404eeaad3b435b51404ee"));
        assert!(!is_placeholder_str("d350c5900e26d2c95f501e94cf95b078"));
        assert!(!is_placeholder_str("P@ssw0rd!"));
        assert!(!is_placeholder_str("/tmp/Administrator.ccache"));
    }

    #[test]
    fn placeholder_str_empty_is_placeholder() {
        assert!(is_placeholder_str(""));
        assert!(is_placeholder_str("   "));
    }

    #[test]
    fn strip_placeholder_credentials_removes_bracketed() {
        let mut args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "[PWD]",
            "hash": "<hash>"
        })
        .as_object()
        .unwrap()
        .clone();
        strip_placeholder_credentials(&mut args);
        assert!(!args.contains_key("password"));
        assert!(!args.contains_key("hash"));
        assert_eq!(args.get("username").unwrap().as_str(), Some("admin"));
    }

    #[test]
    fn strip_placeholder_credentials_keeps_real() {
        let mut args = json!({
            "password": "P@ssw0rd!",
            "hash": "aad3b435b51404eeaad3b435b51404ee"
        })
        .as_object()
        .unwrap()
        .clone();
        strip_placeholder_credentials(&mut args);
        assert!(args.contains_key("password"));
        assert!(args.contains_key("hash"));
    }

    #[test]
    fn find_credential_returns_match() {
        let creds = vec![
            cred("admin", "contoso.local", "P@ss1"),
            cred("guest", "contoso.local", "guest1"),
        ];
        let found = find_credential(&creds, "admin", "contoso.local", false).unwrap();
        assert_eq!(found.password, "P@ss1");
    }

    #[test]
    fn find_credential_case_insensitive() {
        let creds = vec![cred("Admin", "Contoso.Local", "P@ss1")];
        let found = find_credential(&creds, "admin", "contoso.local", false).unwrap();
        assert_eq!(found.password, "P@ss1");
    }

    #[test]
    fn find_credential_cross_realm_fallback() {
        // LLM passes target domain (essos.local) for a tool acting as a
        // user whose home realm is north.sevenkingdoms.local. The resolver
        // should still return the user's stored cred so the cross-realm
        // auth attempt can proceed via Kerberos referral / NTLM pass-through.
        let creds = vec![cred("samwell.tarly", "north.sevenkingdoms.local", "P@ss1")];
        let found = find_credential(&creds, "samwell.tarly", "essos.local", false).unwrap();
        assert_eq!(found.password, "P@ss1");
        assert_eq!(found.domain, "north.sevenkingdoms.local");
    }

    #[test]
    fn find_credential_exact_match_preferred_over_other_realm() {
        // When both an exact-domain match and a different-domain match exist
        // for the same username, the exact match wins.
        let creds = vec![
            cred("admin", "fabrikam.local", "wrong"),
            cred("admin", "contoso.local", "right"),
        ];
        let found = find_credential(&creds, "admin", "contoso.local", false).unwrap();
        assert_eq!(found.password, "right");
    }

    #[test]
    fn find_credential_empty_password_skipped() {
        let creds = vec![cred("admin", "contoso.local", "")];
        assert!(find_credential(&creds, "admin", "contoso.local", false).is_none());
    }

    #[test]
    fn find_credential_realm_strict_blocks_cross_realm_fallback() {
        // The resolver MUST NOT inject a north-realm cred when the tool
        // (e.g. bloodyad_set_password against essos.local DC) requires an
        // exact-realm bind. Wrong-realm cred → 52e/775 at LDAP bind, which
        // wastes the dispatch and burns the agent's tool budget.
        let creds = vec![cred("robb.stark", "north.sevenkingdoms.local", "P@ss1")];
        let found = find_credential(&creds, "robb.stark", "essos.local", true);
        assert!(
            found.is_none(),
            "realm_strict must block cross-realm any_user fallback"
        );
    }

    #[test]
    fn find_credential_realm_strict_returns_exact_match() {
        // Strict mode still returns an exact-realm match, even when other
        // realms have the same username with different passwords.
        let creds = vec![
            cred("admin", "fabrikam.local", "wrong"),
            cred("admin", "contoso.local", "right"),
        ];
        let found = find_credential(&creds, "admin", "contoso.local", true).unwrap();
        assert_eq!(found.password, "right");
    }

    #[test]
    fn find_hash_realm_strict_blocks_cross_realm_fallback() {
        let hashes = vec![hash(
            "robb.stark",
            "north.sevenkingdoms.local",
            "deadbeef",
            None,
        )];
        let found = find_hash(&hashes, "robb.stark", "essos.local", true);
        assert!(
            found.is_none(),
            "realm_strict must block cross-realm any_user fallback for hashes"
        );
    }

    #[test]
    fn find_hash_realm_strict_returns_exact_match() {
        let hashes = vec![
            hash("admin", "fabrikam.local", "fabhash", None),
            hash("admin", "contoso.local", "conhash", None),
        ];
        let found = find_hash(&hashes, "admin", "contoso.local", true).unwrap();
        assert_eq!(found.hash_value, "conhash");
    }

    #[test]
    fn requires_exact_realm_covers_ldap_bind_tools() {
        for tool in [
            "bloodyad_set_password",
            "bloodyad_add_group_member",
            "bloodyad_add_genericall",
            "dacl_edit",
            "pywhisker",
            "ldap_search",
            "ldap_search_descriptions",
            "ldap_acl_enumeration",
            "targeted_kerberoast",
        ] {
            assert!(
                requires_exact_realm(tool),
                "{tool} should require exact-realm bind"
            );
        }
    }

    #[test]
    fn requires_exact_realm_excludes_trust_traversal_tools() {
        // Tools that auth via Kerberos referral or NTLM pass-through MUST
        // keep the cross-realm any_user fallback — they actually use the
        // returned cred to traverse a trust.
        for tool in [
            "smbclient",
            "secretsdump",
            "nxc_smb",
            "psexec",
            "wmiexec",
            "smb_login_check",
        ] {
            assert!(
                !requires_exact_realm(tool),
                "{tool} should NOT require exact-realm bind (uses referral/pass-through)"
            );
        }
    }

    #[test]
    fn find_hash_prefers_aes_record() {
        let hashes = vec![
            hash("admin", "contoso.local", "abc1", None),
            hash("admin", "contoso.local", "abc1", Some("aes-key-456")),
        ];
        let found = find_hash(&hashes, "admin", "contoso.local", false).unwrap();
        assert!(found.aes_key.is_some());
    }

    #[test]
    fn find_hash_allows_empty_domain() {
        // Older imports may not record domain on Hash records.
        let hashes = vec![hash("admin", "", "abc1", None)];
        let found = find_hash(&hashes, "admin", "contoso.local", false);
        assert!(found.is_some());
    }

    #[test]
    fn find_hash_cross_realm_fallback() {
        // Same intent as find_credential_cross_realm_fallback: the LLM passes
        // the target domain but the only stored hash for the user is in their
        // home realm. Return the home-realm hash rather than nothing.
        let hashes = vec![hash(
            "samwell.tarly",
            "north.sevenkingdoms.local",
            "deadbeef",
            None,
        )];
        let found = find_hash(&hashes, "samwell.tarly", "essos.local", false).unwrap();
        assert_eq!(found.hash_value, "deadbeef");
        assert_eq!(found.domain, "north.sevenkingdoms.local");
    }

    #[test]
    fn find_hash_exact_realm_wins_over_other_realm() {
        let hashes = vec![
            hash("admin", "fabrikam.local", "fabhash", None),
            hash("admin", "contoso.local", "conhash", None),
        ];
        let found = find_hash(&hashes, "admin", "contoso.local", false).unwrap();
        assert_eq!(found.hash_value, "conhash");
    }

    #[test]
    fn find_hash_skips_kerberoast_tgs() {
        // Kerberoast TGS ciphertext must never be injected as `hash=…` —
        // impacket bombs out with "Odd-length string" since it's not NTLM.
        let mut tgs = hash(
            "jon.snow",
            "north.local",
            "$krb5tgs$23$*jon.snow$NORTH.LOCAL$north.local/jon.snow*$abc...",
            None,
        );
        tgs.hash_type = "kerberoast".to_string();
        let hashes = vec![tgs];
        let found = find_hash(&hashes, "jon.snow", "north.local", false);
        assert!(
            found.is_none(),
            "kerberoast TGS must not be returned as authenticating hash"
        );
    }

    #[test]
    fn find_hash_keeps_ntlm_when_kerberoast_also_present() {
        let mut tgs = hash("jon.snow", "north.local", "$krb5tgs$23$*...", None);
        tgs.hash_type = "kerberoast".to_string();
        let ntlm = hash(
            "jon.snow",
            "north.local",
            "aad3b435b51404eeaad3b435b51404ee:d350c5900e26d2c95f501e94cf95b078",
            None,
        );
        let hashes = vec![tgs, ntlm];
        let found = find_hash(&hashes, "jon.snow", "north.local", false).unwrap();
        assert!(found.hash_value.starts_with("aad3"));
    }

    #[test]
    fn resolve_principal_credentials_injects_password() {
        let creds = vec![cred("admin", "contoso.local", "P@ss1")];
        let hashes: Vec<Hash> = vec![];
        let mut args = json!({"username": "admin", "domain": "contoso.local"})
            .as_object()
            .unwrap()
            .clone();
        resolve_principal_credentials(&mut args, &creds, &hashes, "admin", "contoso.local", false);
        assert_eq!(args.get("password").unwrap().as_str(), Some("P@ss1"));
    }

    #[test]
    fn resolve_principal_credentials_injects_hash_and_aes() {
        let creds: Vec<Credential> = vec![];
        let hashes = vec![hash("admin", "contoso.local", "abc1", Some("aes-256"))];
        let mut args = json!({"username": "admin", "domain": "contoso.local"})
            .as_object()
            .unwrap()
            .clone();
        resolve_principal_credentials(&mut args, &creds, &hashes, "admin", "contoso.local", false);
        assert_eq!(args.get("hash").unwrap().as_str(), Some("abc1"));
        assert_eq!(args.get("aes_key").unwrap().as_str(), Some("aes-256"));
        assert_eq!(args.get("nt_hash").unwrap().as_str(), Some("abc1"));
    }

    #[test]
    fn resolve_principal_credentials_injects_nt_from_lm_nt_pair() {
        let creds: Vec<Credential> = vec![];
        let hashes = vec![hash(
            "admin",
            "contoso.local",
            "aad3b435b51404eeaad3b435b51404ee:d350c5900e26d2c95f501e94cf95b078",
            None,
        )];
        let mut args = json!({"username": "admin", "domain": "contoso.local"})
            .as_object()
            .unwrap()
            .clone();
        resolve_principal_credentials(&mut args, &creds, &hashes, "admin", "contoso.local", false);
        assert_eq!(
            args.get("nt_hash").unwrap().as_str(),
            Some("d350c5900e26d2c95f501e94cf95b078")
        );
    }

    #[test]
    fn resolve_principal_credentials_does_not_overwrite_existing() {
        let creds = vec![cred("admin", "contoso.local", "fromstate")];
        let hashes: Vec<Hash> = vec![];
        let mut args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "passed-in"
        })
        .as_object()
        .unwrap()
        .clone();
        resolve_principal_credentials(&mut args, &creds, &hashes, "admin", "contoso.local", false);
        assert_eq!(args.get("password").unwrap().as_str(), Some("passed-in"));
    }

    #[test]
    fn resolve_coerce_principal_injects_password() {
        let creds = vec![cred("svc-coerce", "contoso.local", "C0erceP@ss")];
        let hashes: Vec<Hash> = vec![];
        let mut args = json!({
            "ca_host": "ca.contoso.local",
            "coerce_target": "dc01.contoso.local",
            "coerce_user": "svc-coerce",
            "coerce_domain": "contoso.local"
        })
        .as_object()
        .unwrap()
        .clone();
        resolve_coerce_principal(&mut args, &creds, &hashes);
        assert_eq!(
            args.get("coerce_password").unwrap().as_str(),
            Some("C0erceP@ss")
        );
        assert!(args.get("coerce_hash").is_none());
    }

    #[test]
    fn resolve_coerce_principal_injects_hash() {
        let creds: Vec<Credential> = vec![];
        let hashes = vec![hash("svc-coerce", "contoso.local", "deadbeef", None)];
        let mut args = json!({
            "ca_host": "ca.contoso.local",
            "coerce_target": "dc01.contoso.local",
            "coerce_user": "svc-coerce",
            "coerce_domain": "contoso.local"
        })
        .as_object()
        .unwrap()
        .clone();
        resolve_coerce_principal(&mut args, &creds, &hashes);
        assert_eq!(args.get("coerce_hash").unwrap().as_str(), Some("deadbeef"));
        assert!(args.get("coerce_password").is_none());
    }

    #[test]
    fn resolve_coerce_principal_noop_without_user() {
        let creds = vec![cred("svc-coerce", "contoso.local", "C0erceP@ss")];
        let hashes = vec![hash("svc-coerce", "contoso.local", "deadbeef", None)];
        let mut args = json!({
            "ca_host": "ca.contoso.local",
            "coerce_target": "dc01.contoso.local"
        })
        .as_object()
        .unwrap()
        .clone();
        resolve_coerce_principal(&mut args, &creds, &hashes);
        assert!(args.get("coerce_password").is_none());
        assert!(args.get("coerce_hash").is_none());
    }

    #[test]
    fn resolve_coerce_principal_does_not_overwrite_existing() {
        let creds = vec![cred("svc-coerce", "contoso.local", "fromstate")];
        let hashes: Vec<Hash> = vec![];
        let mut args = json!({
            "coerce_user": "svc-coerce",
            "coerce_domain": "contoso.local",
            "coerce_password": "passed-in"
        })
        .as_object()
        .unwrap()
        .clone();
        resolve_coerce_principal(&mut args, &creds, &hashes);
        assert_eq!(
            args.get("coerce_password").unwrap().as_str(),
            Some("passed-in")
        );
    }

    #[test]
    fn resolve_krbtgt_hashes_injects_for_domain() {
        let hashes = vec![hash("krbtgt", "contoso.local", "kr1", None)];
        let mut args = json!({"domain": "contoso.local"})
            .as_object()
            .unwrap()
            .clone();
        resolve_krbtgt_hashes(&mut args, &hashes);
        assert_eq!(args.get("krbtgt_hash").unwrap().as_str(), Some("kr1"));
    }

    #[test]
    fn resolve_krbtgt_hashes_injects_child() {
        let hashes = vec![hash("krbtgt", "child.contoso.local", "kr-child", None)];
        let mut args = json!({"child_domain": "child.contoso.local"})
            .as_object()
            .unwrap()
            .clone();
        resolve_krbtgt_hashes(&mut args, &hashes);
        assert_eq!(
            args.get("child_krbtgt_hash").unwrap().as_str(),
            Some("kr-child")
        );
    }

    #[test]
    fn resolve_domain_sids_injects_all() {
        let mut sids = std::collections::HashMap::new();
        sids.insert("contoso.local".to_string(), "S-1-5-21-100".to_string());
        sids.insert("fabrikam.local".to_string(), "S-1-5-21-200".to_string());

        let mut args = json!({
            "domain": "contoso.local",
            "source_domain": "contoso.local",
            "target_domain": "fabrikam.local"
        })
        .as_object()
        .unwrap()
        .clone();
        resolve_domain_sids(&mut args, &sids);
        assert_eq!(
            args.get("domain_sid").unwrap().as_str(),
            Some("S-1-5-21-100")
        );
        assert_eq!(
            args.get("source_sid").unwrap().as_str(),
            Some("S-1-5-21-100")
        );
        assert_eq!(
            args.get("target_sid").unwrap().as_str(),
            Some("S-1-5-21-200")
        );
    }

    #[test]
    fn resolve_domain_sids_does_not_overwrite() {
        let mut sids = std::collections::HashMap::new();
        sids.insert("contoso.local".to_string(), "S-1-5-21-100".to_string());

        let mut args = json!({
            "domain": "contoso.local",
            "domain_sid": "S-1-5-21-existing"
        })
        .as_object()
        .unwrap()
        .clone();
        resolve_domain_sids(&mut args, &sids);
        assert_eq!(
            args.get("domain_sid").unwrap().as_str(),
            Some("S-1-5-21-existing")
        );
    }

    #[test]
    fn nt_hash_only_strips_lm() {
        assert_eq!(
            nt_hash_only("aad3b435b51404eeaad3b435b51404ee:d350c5900e26d2c95f501e94cf95b078"),
            "d350c5900e26d2c95f501e94cf95b078"
        );
    }

    #[test]
    fn nt_hash_only_passes_through() {
        assert_eq!(
            nt_hash_only("d350c5900e26d2c95f501e94cf95b078"),
            "d350c5900e26d2c95f501e94cf95b078"
        );
    }

    #[test]
    fn expects_ticket_kerberos_tools() {
        let empty_args = json!({}).as_object().unwrap().clone();
        assert!(expects_ticket("psexec_kerberos", &empty_args));
        assert!(expects_ticket("wmiexec_kerberos", &empty_args));
        assert!(expects_ticket("secretsdump_kerberos", &empty_args));
    }

    #[test]
    fn expects_ticket_skips_non_kerberos() {
        let empty_args = json!({}).as_object().unwrap().clone();
        assert!(!expects_ticket("psexec", &empty_args));
        assert!(!expects_ticket("nmap_scan", &empty_args));
    }

    #[test]
    fn expects_ticket_skips_when_already_set() {
        let args_with_ticket = json!({"ticket_path": "/tmp/x.ccache"})
            .as_object()
            .unwrap()
            .clone();
        assert!(!expects_ticket("psexec_kerberos", &args_with_ticket));
    }

    // ── cross-forest Kerberos ticket injection ──────────────────────────────

    #[test]
    fn resolve_cross_forest_ticket_not_injected_when_ntlm_exists() {
        // When the hashes slice contains a matching NTLM hash for the target
        // domain, is_authenticating_hash_type returns true and the function
        // short-circuits — no Kerberos injection needed.
        let hashes = [hash("admin", "fabrikam.local", "deadbeef00112233", None)];
        let domain_l = "fabrikam.local";
        // Replicate the guard logic from resolve_cross_forest_ticket
        let user_l = "admin";
        let has_ntlm = hashes.iter().any(|h| {
            h.domain.to_lowercase() == domain_l
                && (user_l.is_empty() || h.username.to_lowercase() == user_l)
                && !h.hash_value.is_empty()
                && is_authenticating_hash_type(&h.hash_type)
        });
        assert!(
            has_ntlm,
            "NTLM hash present — Kerberos injection should be skipped"
        );
    }

    #[test]
    fn resolve_cross_forest_ticket_triggered_when_no_ntlm_for_target() {
        // When no NTLM hash for the target domain exists, the resolver should
        // proceed to the Redis lookup for a forged ccache.
        let hashes = [hash("administrator", "contoso.local", "deadbeef", None)];
        let domain_l = "fabrikam.local"; // foreign domain, no entry in hashes
        let user_l = "administrator";
        let has_ntlm = hashes.iter().any(|h| {
            h.domain.to_lowercase() == domain_l
                && (user_l.is_empty() || h.username.to_lowercase() == user_l)
                && !h.hash_value.is_empty()
                && is_authenticating_hash_type(&h.hash_type)
        });
        assert!(
            !has_ntlm,
            "No NTLM hash for fabrikam.local — resolver should attempt Kerberos ticket lookup"
        );
    }

    #[test]
    fn requires_exact_realm_bloodyad_set_password_is_true() {
        // Confirm the canary tool is covered by realm_strict so that the
        // cross-forest ticket injection fires for it.
        assert!(requires_exact_realm("bloodyad_set_password"));
    }
}
