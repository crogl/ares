//! auto_sid_enumeration -- enumerate domain SIDs and well-known SID mappings.
//!
//! Queries each discovered DC via LDAP to resolve the domain SID, then maps
//! well-known RIDs (500=Administrator, 502=krbtgt, 512=Domain Admins, etc.)
//! to confirm account names. This is useful when the RID-500 account has
//! been renamed (e.g., not "Administrator").
//!
//! Also discovers the domain SID needed for golden ticket forging and
//! ExtraSid attacks.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Collect SID enumeration work items from current state.
///
/// Pure logic extracted from `auto_sid_enumeration` so it can be unit-tested
/// without needing a `Dispatcher` or async runtime.
fn collect_sid_enum_work(state: &StateInner) -> Vec<SidEnumWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();

    for (domain, dc_ip) in &state.all_domains_with_dcs() {
        // Skip if we already have the SID for this domain
        if state.domain_sids.contains_key(domain) {
            continue;
        }

        let dedup_key = format!("sid_enum:{}", domain.to_lowercase());
        if state.is_processed(DEDUP_SID_ENUMERATION, &dedup_key) {
            continue;
        }

        let cred = match state
            .credentials
            .iter()
            .find(|c| {
                !c.password.is_empty()
                    && c.domain.to_lowercase() == domain.to_lowercase()
                    && !state.is_principal_quarantined(&c.username, &c.domain)
            })
            .or_else(|| {
                state.credentials.iter().find(|c| {
                    !c.password.is_empty()
                        && !state.is_principal_quarantined(&c.username, &c.domain)
                })
            }) {
            Some(c) => c.clone(),
            None => continue,
        };

        items.push(SidEnumWork {
            dedup_key,
            domain: domain.clone(),
            dc_ip: dc_ip.clone(),
            credential: cred,
        });
    }

    items
}

/// Enumerate domain SIDs and well-known accounts.
/// Interval: 45s.
pub async fn auto_sid_enumeration(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(45));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if !dispatcher.is_technique_allowed("sid_enumeration") {
            continue;
        }

        let work: Vec<SidEnumWork> = {
            let state = dispatcher.state.read().await;
            collect_sid_enum_work(&state)
        };

        for item in work {
            // Cross-forest authenticated RPC/LDAP from the source forest's
            // credential typically returns ACCESS_DENIED — but `rpcclient
            // -U "" -N -c lsaquery` over a null session usually succeeds
            // against DCs that allow anonymous LSA queries (most legacy
            // configurations). The agent loop won't try the null-session
            // path on its own when handed a credential, so we explicitly
            // instruct it to fall through. The result-processor's
            // `extract_lsaquery_domain_sid` regex captures the resulting
            // `Domain Name: / Domain Sid:` block and caches it against the
            // domain, which unblocks `forge_inter_realm_and_dump`.
            let cred_is_cross_forest = !item
                .credential
                .domain
                .to_lowercase()
                .ends_with(&item.domain.to_lowercase())
                && !item
                    .domain
                    .to_lowercase()
                    .ends_with(&item.credential.domain.to_lowercase())
                && item.credential.domain.to_lowercase() != item.domain.to_lowercase();
            let instructions = if cred_is_cross_forest {
                Some(format!(
                    "Resolve the domain SID and RID-500 account name for {dom} ({dc}). \
                     The provided credential is from a different forest and authenticated \
                     RPC/LDAP from outside this forest typically fails with ACCESS_DENIED. \
                     Run `rpcclient -U \"\" -N {dc} -c \"lsaquery\"` first (null/anonymous \
                     session — no credential needed) to capture the `Domain Name:` and \
                     `Domain Sid:` lines. Then run `impacket-lookupsid` with the provided \
                     credential as a secondary attempt for RID-500 mapping. Report both \
                     outputs verbatim via task_complete tool_outputs so the parser can \
                     extract the SID.",
                    dom = item.domain,
                    dc = item.dc_ip,
                ))
            } else {
                None
            };

            let mut payload = json!({
                "technique": "sid_enumeration",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });
            if let Some(text) = instructions {
                payload["instructions"] = json!(text);
            }

            let priority = dispatcher.effective_priority("sid_enumeration");
            match dispatcher
                .throttled_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        "SID enumeration dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_SID_ENUMERATION, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SID_ENUMERATION, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "SID enumeration deferred");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch SID enumeration");
                }
            }
        }
    }
}

struct SidEnumWork {
    dedup_key: String,
    domain: String,
    dc_ip: String,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key = format!("sid_enum:{}", "contoso.local");
        assert_eq!(key, "sid_enum:contoso.local");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_SID_ENUMERATION, "sid_enumeration");
    }

    #[test]
    fn payload_structure_has_correct_technique() {
        let cred = ares_core::models::Credential {
            id: "c1".into(),
            username: "admin".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };
        let payload = json!({
            "technique": "sid_enumeration",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });
        assert_eq!(payload["technique"], "sid_enumeration");
        assert_eq!(payload["target_ip"], "192.168.58.10");
        assert_eq!(payload["domain"], "contoso.local");
    }

    #[test]
    fn work_struct_construction() {
        let cred = ares_core::models::Credential {
            id: "c1".into(),
            username: "admin".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };
        let work = SidEnumWork {
            dedup_key: "sid_enum:contoso.local".into(),
            domain: "contoso.local".into(),
            dc_ip: "192.168.58.10".into(),
            credential: cred,
        };
        assert_eq!(work.domain, "contoso.local");
        assert_eq!(work.dc_ip, "192.168.58.10");
        assert_eq!(work.credential.username, "admin");
    }

    #[test]
    fn dedup_key_normalizes_domain() {
        let key = format!("sid_enum:{}", "CONTOSO.LOCAL".to_lowercase());
        assert_eq!(key, "sid_enum:contoso.local");
    }

    #[test]
    fn dedup_keys_differ_per_domain() {
        let key1 = format!("sid_enum:{}", "contoso.local");
        let key2 = format!("sid_enum:{}", "fabrikam.local");
        assert_ne!(key1, key2);
    }

    fn make_credential(
        username: &str,
        password: &str,
        domain: &str,
    ) -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: format!("c-{username}"),
            username: username.into(),
            password: password.into(), // pragma: allowlist secret
            domain: domain.into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        }
    }

    #[test]
    fn collect_empty_state_no_work() {
        let state = StateInner::new("test-op".into());
        let work = collect_sid_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credentials_no_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = collect_sid_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_single_domain_with_cred() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_sid_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].dc_ip, "192.168.58.10");
        assert_eq!(work[0].credential.username, "admin");
    }

    #[test]
    fn collect_skips_domain_with_known_sid() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .domain_sids
            .insert("contoso.local".into(), "S-1-5-21-1234".into());
        let work = collect_sid_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_dedup_skips_processed() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.mark_processed(DEDUP_SID_ENUMERATION, "sid_enum:contoso.local".into());
        let work = collect_sid_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_cross_domain_fallback() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("crossuser", "P@ssw0rd!", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_sid_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "crossuser");
        assert_eq!(work[0].credential.domain, "fabrikam.local");
    }

    #[test]
    fn collect_skips_empty_password() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "", "contoso.local"));
        let work = collect_sid_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_quarantined_credential_skipped() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("baduser", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.quarantine_principal("baduser", "contoso.local");
        let work = collect_sid_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_dedup_key_lowercased() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("CONTOSO.LOCAL".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_sid_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dedup_key, "sid_enum:contoso.local");
    }

    #[tokio::test]
    async fn collect_via_shared_state() {
        let shared = SharedState::new("test-op".into());
        {
            let mut state = shared.write().await;
            state
                .domain_controllers
                .insert("contoso.local".into(), "192.168.58.10".into());
            state
                .credentials
                .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        }
        let state = shared.read().await;
        let work = collect_sid_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
    }
}
