//! auto_adcs_enumeration -- detect ADCS servers via CertEnroll share.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Extract domain from an ADCS host's FQDN.
/// e.g. "srv01.fabrikam.local" -> "fabrikam.local"
fn extract_domain_from_fqdn(fqdn: &str) -> Option<String> {
    fqdn.to_lowercase()
        .split_once('.')
        .map(|(_, d)| d.to_string())
}

/// Work item for ADCS enumeration.
struct AdcsWork {
    host_ip: String,
    domain: String,
    credential: ares_core::models::Credential,
}

/// Collect ADCS enumeration work items from current state.
///
/// Pure logic extracted from `auto_adcs_enumeration` so it can be unit-tested
/// without needing a `Dispatcher` or async runtime.
fn collect_adcs_work(state: &StateInner) -> Vec<AdcsWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    state
        .shares
        .iter()
        .filter(|s| s.name.to_lowercase() == "certenroll")
        .filter(|s| !state.is_processed(DEDUP_ADCS_SERVERS, &s.host))
        .filter_map(|s| {
            let host_lower = s.host.to_lowercase();
            let domain = state
                .hosts
                .iter()
                .find(|h| h.ip == s.host || h.hostname.to_lowercase() == host_lower)
                .and_then(|h| extract_domain_from_fqdn(&h.hostname))
                .and_then(|d| {
                    if state.domains.iter().any(|known| known.to_lowercase() == d) {
                        Some(d)
                    } else {
                        state
                            .domains
                            .iter()
                            .find(|known| d.ends_with(&format!(".{}", known.to_lowercase())))
                            .or_else(|| {
                                state
                                    .domains
                                    .iter()
                                    .find(|known| known.to_lowercase().ends_with(&format!(".{d}")))
                            })
                            .cloned()
                            .or(Some(d))
                    }
                })
                .or_else(|| state.domains.first().cloned())?;

            let cred = state
                .credentials
                .iter()
                .find(|c| {
                    !c.password.is_empty()
                        && c.domain.to_lowercase() == domain.to_lowercase()
                        && !state.is_delegation_account(&c.username)
                        && !state.is_credential_quarantined(&c.username, &c.domain)
                })
                .or_else(|| {
                    state.credentials.iter().find(|c| {
                        !c.password.is_empty()
                            && !state.is_delegation_account(&c.username)
                            && !state.is_credential_quarantined(&c.username, &c.domain)
                    })
                })
                .or_else(|| state.credentials.first())
                .cloned()?;

            Some(AdcsWork {
                host_ip: s.host.clone(),
                domain,
                credential: cred,
            })
        })
        .collect()
}

/// Detects ADCS servers by looking for CertEnroll shares and dispatches certipy_find.
/// Interval: 30s. Matches Python `_auto_adcs_enumeration`.
pub async fn auto_adcs_enumeration(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
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

        let work = {
            let state = dispatcher.state.read().await;
            collect_adcs_work(&state)
        };

        for item in work {
            match dispatcher
                .request_certipy_find(&item.host_ip, &item.domain, &item.credential)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(task_id = %task_id, host = %item.host_ip, "ADCS enumeration dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_ADCS_SERVERS, item.host_ip.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_ADCS_SERVERS, &item.host_ip)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch ADCS enumeration"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::{Credential, Host, Share};

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

    fn make_share(host: &str, name: &str) -> Share {
        Share {
            host: host.into(),
            name: name.into(),
            permissions: String::new(),
            comment: String::new(),
        }
    }

    // --- collect_adcs_work tests ---

    #[test]
    fn collect_empty_state_returns_no_work() {
        let state = StateInner::new("test-op".into());
        let work = collect_adcs_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credentials_returns_no_work() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        let work = collect_adcs_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_certenroll_share_produces_work() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.contoso.local", false));
        state.domains.push("contoso.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_adcs_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].host_ip, "192.168.58.50");
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].credential.username, "admin");
    }

    #[test]
    fn collect_dedup_skips_already_processed() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.contoso.local", false));
        state.domains.push("contoso.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.mark_processed(DEDUP_ADCS_SERVERS, "192.168.58.50".into());
        let work = collect_adcs_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_non_certenroll_share_ignored() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "SYSVOL"));
        state
            .hosts
            .push(make_host("192.168.58.50", "dc01.contoso.local", true));
        state.domains.push("contoso.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_adcs_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_prefers_same_domain_credential() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.fabrikam.local", false));
        state.domains.push("fabrikam.local".into());
        state
            .credentials
            .push(make_credential("crossuser", "Cross!1", "contoso.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("fabadmin", "Fab!Pass1", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_adcs_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "fabadmin");
    }

    #[test]
    fn collect_falls_back_to_first_domain_when_no_host_match() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        // No matching host in state.hosts
        state.domains.push("contoso.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_adcs_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
    }

    #[test]
    fn collect_certenroll_case_insensitive() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "certenroll"));
        state.domains.push("contoso.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_adcs_work(&state);
        assert_eq!(work.len(), 1);
    }

    #[test]
    fn collect_multiple_adcs_hosts() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state.shares.push(make_share("192.168.58.51", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.contoso.local", false));
        state
            .hosts
            .push(make_host("192.168.58.51", "ca02.fabrikam.local", false));
        state.domains.push("contoso.local".into());
        state.domains.push("fabrikam.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("fabadmin", "Fab!Pass1", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_adcs_work(&state);
        assert_eq!(work.len(), 2);
    }

    #[test]
    fn collect_quarantined_credential_falls_back() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.contoso.local", false));
        state.domains.push("contoso.local".into());
        state
            .credentials
            .push(make_credential("baduser", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("gooduser", "Pass!456", "fabrikam.local")); // pragma: allowlist secret
        state.quarantine_credential("baduser", "contoso.local");
        let work = collect_adcs_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "gooduser");
    }

    #[test]
    fn extract_domain_from_fqdn_typical() {
        assert_eq!(
            extract_domain_from_fqdn("srv01.fabrikam.local"),
            Some("fabrikam.local".to_string())
        );
    }

    #[test]
    fn extract_domain_from_fqdn_nested() {
        assert_eq!(
            extract_domain_from_fqdn("host.child.contoso.local"),
            Some("child.contoso.local".to_string())
        );
    }

    #[test]
    fn extract_domain_from_fqdn_case_insensitive() {
        assert_eq!(
            extract_domain_from_fqdn("DC01.CONTOSO.LOCAL"),
            Some("contoso.local".to_string())
        );
    }

    #[test]
    fn extract_domain_from_fqdn_bare_hostname() {
        assert_eq!(extract_domain_from_fqdn("dc01"), None);
    }

    #[test]
    fn extract_domain_from_fqdn_empty() {
        assert_eq!(extract_domain_from_fqdn(""), None);
    }

    #[test]
    fn extract_domain_from_fqdn_trailing_dot() {
        // "host." splits into ("host", "") -> Some("")
        assert_eq!(extract_domain_from_fqdn("host."), Some("".to_string()));
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_ADCS_SERVERS, "adcs_servers");
    }

    #[test]
    fn certenroll_share_name_match() {
        let share_name = "CertEnroll";
        assert_eq!(share_name.to_lowercase(), "certenroll");
    }

    #[test]
    fn certenroll_case_insensitive() {
        let names = vec!["CertEnroll", "certenroll", "CERTENROLL"];
        for name in names {
            assert_eq!(name.to_lowercase(), "certenroll");
        }
    }

    #[test]
    fn domain_resolution_from_fqdn() {
        // Verifies domain extraction works for typical ADCS hosts
        assert_eq!(
            extract_domain_from_fqdn("ca01.contoso.local"),
            Some("contoso.local".to_string())
        );
        assert_eq!(
            extract_domain_from_fqdn("ca01.fabrikam.local"),
            Some("fabrikam.local".to_string())
        );
    }

    #[test]
    fn credential_selection_prefers_same_domain() {
        let creds = [
            ares_core::models::Credential {
                id: "c1".into(),
                username: "admin".into(),
                password: "P@ssw0rd!".into(), // pragma: allowlist secret
                domain: "contoso.local".into(),
                source: "test".into(),
                is_admin: false,
                discovered_at: None,
                parent_id: None,
                attack_step: 0,
            },
            ares_core::models::Credential {
                id: "c2".into(),
                username: "admin2".into(),
                password: "P@ssw0rd!".into(), // pragma: allowlist secret
                domain: "fabrikam.local".into(),
                source: "test".into(),
                is_admin: false,
                discovered_at: None,
                parent_id: None,
                attack_step: 0,
            },
        ];
        let target_domain = "fabrikam.local";
        let selected = creds.iter().find(|c| {
            !c.password.is_empty() && c.domain.to_lowercase() == target_domain.to_lowercase()
        });
        assert!(selected.is_some());
        assert_eq!(selected.unwrap().domain, "fabrikam.local");
    }
}
