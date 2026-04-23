//! auto_ldap_signing -- check LDAP signing enforcement per DC.
//!
//! When LDAP signing is not required, attackers can relay NTLM auth to LDAP
//! for shadow credentials, RBCD writes, or account takeover. This module
//! dispatches a check per DC to test whether LDAP channel binding and
//! signing are enforced.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Checks each DC for LDAP signing and channel binding enforcement.
/// Interval: 45s.
pub async fn auto_ldap_signing(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("ldap_signing") {
            continue;
        }

        let work: Vec<LdapSigningWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() {
                continue;
            }

            let mut items = Vec::new();

            for (domain, dc_ip) in &state.domain_controllers {
                let dedup_key = format!("ldap_sign:{}", dc_ip);
                if state.is_processed(DEDUP_LDAP_SIGNING, &dedup_key) {
                    continue;
                }

                let cred = match state
                    .credentials
                    .iter()
                    .find(|c| c.domain.to_lowercase() == domain.to_lowercase())
                    .or_else(|| state.credentials.first())
                {
                    Some(c) => c.clone(),
                    None => continue,
                };

                items.push(LdapSigningWork {
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
                "technique": "ldap_signing_check",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("ldap_signing");
            match dispatcher
                .throttled_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        "LDAP signing check dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_LDAP_SIGNING, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_LDAP_SIGNING, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "LDAP signing check deferred");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch LDAP signing check");
                }
            }
        }
    }
}

struct LdapSigningWork {
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
        let key = format!("ldap_sign:{}", "192.168.58.10");
        assert_eq!(key, "ldap_sign:192.168.58.10");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_LDAP_SIGNING, "ldap_signing");
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
            "technique": "ldap_signing_check",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });
        assert_eq!(payload["technique"], "ldap_signing_check");
        assert_eq!(payload["target_ip"], "192.168.58.10");
        assert_eq!(payload["domain"], "contoso.local");
        assert_eq!(payload["credential"]["username"], "admin");
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
        let work = LdapSigningWork {
            dedup_key: "ldap_sign:192.168.58.10".into(),
            domain: "contoso.local".into(),
            dc_ip: "192.168.58.10".into(),
            credential: cred,
        };
        assert_eq!(work.domain, "contoso.local");
        assert_eq!(work.dc_ip, "192.168.58.10");
        assert_eq!(work.credential.username, "admin");
    }

    #[test]
    fn dedup_key_uses_dc_ip() {
        // LDAP signing dedup is by DC IP, not domain
        let key = format!("ldap_sign:{}", "192.168.58.10");
        assert!(key.starts_with("ldap_sign:"));
        assert!(key.contains("192.168.58.10"));
    }

    #[test]
    fn dedup_keys_differ_per_dc() {
        let key1 = format!("ldap_sign:{}", "192.168.58.10");
        let key2 = format!("ldap_sign:{}", "192.168.58.20");
        assert_ne!(key1, key2);
    }
}
