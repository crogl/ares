//! auto_dns_enum -- DNS zone transfer and record enumeration.
//!
//! Attempts AXFR zone transfers and enumerates DNS records (SRV, A, CNAME)
//! from each discovered DC. DNS records reveal additional hosts, services,
//! and naming conventions that port scanning alone may miss.
//!
//! Zone transfers are often allowed from domain-joined machines, and even
//! when blocked, DNS SRV record enumeration reveals AD-registered services
//! (e.g., _msdcs, _kerberos, _ldap, _gc, _http).

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Collect DNS enumeration work items from current state.
///
/// Pure logic extracted from `auto_dns_enum` so it can be unit-tested
/// without needing a `Dispatcher` or async runtime.
fn collect_dns_enum_work(state: &StateInner) -> Vec<DnsEnumWork> {
    let mut items = Vec::new();

    for (domain, dc_ip) in &state.all_domains_with_dcs() {
        let dedup_key = format!("dns_enum:{}", domain.to_lowercase());
        if state.is_processed(DEDUP_DNS_ENUM, &dedup_key) {
            continue;
        }

        // DNS enum can work without creds (zone transfer, SRV queries)
        // but we pass creds if available for authenticated queries
        let cred = state
            .credentials
            .iter()
            .find(|c| !c.password.is_empty() && c.domain.to_lowercase() == domain.to_lowercase())
            .cloned();

        items.push(DnsEnumWork {
            dedup_key,
            domain: domain.clone(),
            dc_ip: dc_ip.clone(),
            credential: cred,
        });
    }

    items
}

/// DNS enumeration per domain.
/// Interval: 45s.
pub async fn auto_dns_enum(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("dns_enum") {
            continue;
        }

        let work: Vec<DnsEnumWork> = {
            let state = dispatcher.state.read().await;
            collect_dns_enum_work(&state)
        };

        for item in work {
            let mut payload = json!({
                "technique": "dns_enumeration",
                "target_ip": item.dc_ip,
                "domain": item.domain,
            });

            if let Some(ref cred) = item.credential {
                payload["credential"] = json!({
                    "username": cred.username,
                    "password": cred.password,
                    "domain": cred.domain,
                });
            }

            let priority = dispatcher.effective_priority("dns_enum");
            match dispatcher
                .throttled_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        "DNS enumeration dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_DNS_ENUM, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_DNS_ENUM, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "DNS enumeration deferred");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch DNS enumeration");
                }
            }
        }
    }
}

struct DnsEnumWork {
    dedup_key: String,
    domain: String,
    dc_ip: String,
    credential: Option<ares_core::models::Credential>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key = format!("dns_enum:{}", "contoso.local");
        assert_eq!(key, "dns_enum:contoso.local");
    }

    #[test]
    fn dedup_key_normalizes_domain() {
        let key = format!("dns_enum:{}", "CONTOSO.LOCAL".to_lowercase());
        assert_eq!(key, "dns_enum:contoso.local");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_DNS_ENUM, "dns_enum");
    }

    #[test]
    fn no_cred_required() {
        // DNS enum works without credentials for zone transfer / SRV queries
        let cred: Option<ares_core::models::Credential> = None;
        assert!(cred.is_none());
    }

    #[test]
    fn payload_without_cred() {
        let payload = serde_json::json!({
            "technique": "dns_enumeration",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
        });
        assert!(payload.get("credential").is_none());
    }

    #[test]
    fn payload_structure_has_correct_technique() {
        let payload = serde_json::json!({
            "technique": "dns_enumeration",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
        });
        assert_eq!(payload["technique"], "dns_enumeration");
        assert_eq!(payload["target_ip"], "192.168.58.10");
        assert_eq!(payload["domain"], "contoso.local");
    }

    #[test]
    fn payload_with_credential() {
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
        let mut payload = serde_json::json!({
            "technique": "dns_enumeration",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
        });
        payload["credential"] = serde_json::json!({
            "username": cred.username,
            "password": cred.password,
            "domain": cred.domain,
        });
        assert_eq!(payload["credential"]["username"], "admin");
        assert_eq!(payload["credential"]["domain"], "contoso.local");
    }

    #[test]
    fn work_struct_construction() {
        let work = DnsEnumWork {
            dedup_key: "dns_enum:contoso.local".into(),
            domain: "contoso.local".into(),
            dc_ip: "192.168.58.10".into(),
            credential: None,
        };
        assert_eq!(work.domain, "contoso.local");
        assert_eq!(work.dc_ip, "192.168.58.10");
        assert!(work.credential.is_none());
    }

    #[test]
    fn work_struct_with_credential() {
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
        let work = DnsEnumWork {
            dedup_key: "dns_enum:contoso.local".into(),
            domain: "contoso.local".into(),
            dc_ip: "192.168.58.10".into(),
            credential: Some(cred),
        };
        assert!(work.credential.is_some());
        assert_eq!(work.credential.unwrap().username, "admin");
    }

    #[test]
    fn dedup_key_domain_based() {
        let domain1 = "contoso.local";
        let domain2 = "fabrikam.local";
        let key1 = format!("dns_enum:{}", domain1.to_lowercase());
        let key2 = format!("dns_enum:{}", domain2.to_lowercase());
        assert_ne!(key1, key2);
        assert_eq!(key1, "dns_enum:contoso.local");
        assert_eq!(key2, "dns_enum:fabrikam.local");
    }

    #[test]
    fn case_normalization_mixed() {
        let key = format!("dns_enum:{}", "Contoso.Local".to_lowercase());
        assert_eq!(key, "dns_enum:contoso.local");
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
        let work = collect_dns_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_single_domain_no_cred() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = collect_dns_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].dc_ip, "192.168.58.10");
        assert!(work[0].credential.is_none());
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
        let work = collect_dns_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert!(work[0].credential.is_some());
        assert_eq!(work[0].credential.as_ref().unwrap().username, "admin");
    }

    #[test]
    fn collect_dedup_skips_processed() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state.mark_processed(DEDUP_DNS_ENUM, "dns_enum:contoso.local".into());
        let work = collect_dns_enum_work(&state);
        assert!(work.is_empty());
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
        let work = collect_dns_enum_work(&state);
        assert_eq!(work.len(), 2);
    }

    #[test]
    fn collect_skips_empty_password_cred() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "", "contoso.local"));
        let work = collect_dns_enum_work(&state);
        assert_eq!(work.len(), 1);
        // Empty password cred should not be selected
        assert!(work[0].credential.is_none());
    }

    #[test]
    fn collect_cred_only_matches_same_domain() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_dns_enum_work(&state);
        assert_eq!(work.len(), 1);
        // Cross-domain cred should NOT be selected (dns_enum only matches same domain)
        assert!(work[0].credential.is_none());
    }

    #[test]
    fn collect_dedup_key_lowercased() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("CONTOSO.LOCAL".into(), "192.168.58.10".into());
        let work = collect_dns_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dedup_key, "dns_enum:contoso.local");
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
        let work = collect_dns_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
        assert!(work[0].credential.is_some());
    }
}
