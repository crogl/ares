//! auto_certifried -- CVE-2022-26923 machine account DNS hostname spoofing.
//!
//! Certifried abuses the fact that machine accounts can enroll for certificates
//! and the DNS hostname in the certificate is derived from the machine account's
//! dNSHostName attribute. By creating a machine account and setting its
//! dNSHostName to a DC's hostname, you can obtain a certificate that
//! authenticates as the DC.
//!
//! Prerequisites:
//!   - MachineAccountQuota > 0 (default 10)
//!   - Valid domain credential
//!   - ADCS CA discovered
//!
//! Dispatches to "privesc" role with technique "certifried".

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Collect certifried work items from current state.
///
/// Pure logic extracted from `auto_certifried` so it can be unit-tested
/// without needing a `Dispatcher` or async runtime.
fn collect_certifried_work(state: &StateInner) -> Vec<CertifriedWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();

    for (domain, dc_ip) in &state.all_domains_with_dcs() {
        let dedup_key = format!("certifried:{}", domain.to_lowercase());
        if state.is_processed(DEDUP_CERTIFRIED, &dedup_key) {
            continue;
        }

        // Find the DC host to get its hostname for spoofing
        let dc_hostname = state
            .hosts
            .iter()
            .find(|h| h.ip == *dc_ip && h.is_dc)
            .map(|h| h.hostname.clone())
            .filter(|h| !h.is_empty());

        // Need a credential for this domain
        let cred = match state
            .credentials
            .iter()
            .find(|c| {
                c.domain.to_lowercase() == domain.to_lowercase()
                    && !c.password.is_empty()
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

        items.push(CertifriedWork {
            dedup_key,
            domain: domain.clone(),
            dc_ip: dc_ip.clone(),
            dc_hostname,
            credential: cred,
        });
    }

    items
}

/// Dispatches certifried (CVE-2022-26923) per domain with ADCS.
/// Interval: 45s.
pub async fn auto_certifried(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("certifried") {
            continue;
        }

        let work = {
            let state = dispatcher.state.read().await;
            collect_certifried_work(&state)
        };

        for item in work {
            let payload = json!({
                "technique": "certifried",
                "cve": "CVE-2022-26923",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "dc_hostname": item.dc_hostname,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("certifried");
            match dispatcher
                .throttled_submit("exploit", "privesc", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        "Certifried (CVE-2022-26923) dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_CERTIFRIED, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_CERTIFRIED, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "Certifried deferred");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch certifried");
                }
            }
        }
    }
}

struct CertifriedWork {
    dedup_key: String,
    domain: String,
    dc_ip: String,
    dc_hostname: Option<String>,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::{Credential, Host};

    fn make_credential(username: &str, password: &str, domain: &str) -> Credential {
        Credential {
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

    fn make_host(ip: &str, hostname: &str, is_dc: bool) -> Host {
        Host {
            ip: ip.into(),
            hostname: hostname.into(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc,
            owned: false,
        }
    }

    // --- collect_certifried_work tests ---

    #[test]
    fn collect_empty_state_returns_no_work() {
        let state = StateInner::new("test-op".into());
        let work = collect_certifried_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credentials_returns_no_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = collect_certifried_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_single_domain_produces_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_certifried_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].dc_ip, "192.168.58.10");
        assert_eq!(work[0].dedup_key, "certifried:contoso.local");
        assert_eq!(work[0].credential.username, "admin");
    }

    #[test]
    fn collect_dedup_skips_already_processed() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.mark_processed(DEDUP_CERTIFRIED, "certifried:contoso.local".into());
        let work = collect_certifried_work(&state);
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
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("svcacct", "Svc!Pass1", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_certifried_work(&state);
        assert_eq!(work.len(), 2);
        let domains: Vec<&str> = work.iter().map(|w| w.domain.as_str()).collect();
        assert!(domains.contains(&"contoso.local"));
        assert!(domains.contains(&"fabrikam.local"));
    }

    #[test]
    fn collect_dc_hostname_resolved_from_hosts() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .hosts
            .push(make_host("192.168.58.10", "dc01.contoso.local", true));
        let work = collect_certifried_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dc_hostname, Some("dc01.contoso.local".into()));
    }

    #[test]
    fn collect_dc_hostname_none_when_no_host_match() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_certifried_work(&state);
        assert_eq!(work.len(), 1);
        assert!(work[0].dc_hostname.is_none());
    }

    #[test]
    fn collect_prefers_same_domain_credential() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("crossuser", "Cross!1", "fabrikam.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_certifried_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "admin");
    }

    #[test]
    fn collect_falls_back_to_cross_domain_credential() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("crossuser", "Cross!1", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_certifried_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "crossuser");
    }

    #[test]
    fn collect_skips_empty_password_credentials() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "", "contoso.local"));
        let work = collect_certifried_work(&state);
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
        state.quarantine_credential("baduser", "contoso.local");
        let work = collect_certifried_work(&state);
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
        let work = collect_certifried_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dedup_key, "certifried:contoso.local");
    }

    #[test]
    fn dedup_key_format() {
        let key = format!("certifried:{}", "contoso.local");
        assert_eq!(key, "certifried:contoso.local");
    }

    #[test]
    fn dedup_key_normalizes_domain() {
        let key = format!("certifried:{}", "CONTOSO.LOCAL".to_lowercase());
        assert_eq!(key, "certifried:contoso.local");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_CERTIFRIED, "certifried");
    }

    #[test]
    fn dc_hostname_from_hosts() {
        // Simulates finding a DC hostname from hosts list
        let hostname = "dc01.contoso.local";
        let filtered = Some(hostname.to_string()).filter(|h| !h.is_empty());
        assert_eq!(filtered, Some("dc01.contoso.local".to_string()));

        let empty = Some("".to_string()).filter(|h| !h.is_empty());
        assert!(empty.is_none());
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
        let payload = serde_json::json!({
            "technique": "certifried",
            "cve": "CVE-2022-26923",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "dc_hostname": "dc01.contoso.local",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });
        assert_eq!(payload["technique"], "certifried");
        assert_eq!(payload["cve"], "CVE-2022-26923");
        assert_eq!(payload["target_ip"], "192.168.58.10");
        assert_eq!(payload["dc_hostname"], "dc01.contoso.local");
    }

    #[test]
    fn payload_without_dc_hostname() {
        let payload = serde_json::json!({
            "technique": "certifried",
            "cve": "CVE-2022-26923",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "dc_hostname": null,
            "credential": {
                "username": "admin",
                "password": "P@ssw0rd!",
                "domain": "contoso.local",
            },
        });
        assert!(payload["dc_hostname"].is_null());
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
        let work = CertifriedWork {
            dedup_key: "certifried:contoso.local".into(),
            domain: "contoso.local".into(),
            dc_ip: "192.168.58.10".into(),
            dc_hostname: Some("dc01.contoso.local".into()),
            credential: cred,
        };
        assert_eq!(work.domain, "contoso.local");
        assert_eq!(work.dc_ip, "192.168.58.10");
        assert_eq!(work.dc_hostname, Some("dc01.contoso.local".into()));
        assert_eq!(work.credential.username, "admin");
    }

    #[test]
    fn work_struct_without_hostname() {
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
        let work = CertifriedWork {
            dedup_key: "certifried:contoso.local".into(),
            domain: "contoso.local".into(),
            dc_ip: "192.168.58.10".into(),
            dc_hostname: None,
            credential: cred,
        };
        assert!(work.dc_hostname.is_none());
    }
}
