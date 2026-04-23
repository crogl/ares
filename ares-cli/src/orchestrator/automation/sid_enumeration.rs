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

            if state.credentials.is_empty() {
                continue;
            }

            let mut items = Vec::new();

            for (domain, dc_ip) in &state.domain_controllers {
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
                            && !state.is_credential_quarantined(&c.username, &c.domain)
                    })
                    .or_else(|| {
                        state.credentials.iter().find(|c| {
                            !c.password.is_empty()
                                && !state.is_credential_quarantined(&c.username, &c.domain)
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
        };

        for item in work {
            let payload = json!({
                "technique": "sid_enumeration",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

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
}
