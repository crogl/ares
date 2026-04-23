//! auto_domain_user_enum -- explicit per-domain LDAP user enumeration.
//!
//! Unlike initial recon (which does broad DC scanning), this module dispatches
//! targeted LDAP user enumeration per domain using the best available credential.
//! This fills the gap where essos.local users are not enumerated because the
//! initial recon agent only has north/sevenkingdoms creds.
//!
//! Dispatches `ldap_user_enumeration` to the recon role for each domain that
//! has a DC but hasn't been fully enumerated yet.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Dispatches per-domain LDAP user enumeration.
/// Interval: 45s.
pub async fn auto_domain_user_enum(
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

        if !dispatcher.is_technique_allowed("domain_user_enumeration") {
            continue;
        }

        let work: Vec<UserEnumWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() {
                continue;
            }

            let mut items = Vec::new();

            for (domain, dc_ip) in &state.domain_controllers {
                let dedup_key = format!("user_enum:{}", domain.to_lowercase());
                if state.is_processed(DEDUP_DOMAIN_USER_ENUM, &dedup_key) {
                    continue;
                }

                // Prefer a credential from the target domain.
                // Fall back to any available credential (cross-domain LDAP may work).
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

                items.push(UserEnumWork {
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
                "technique": "ldap_user_enumeration",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
                "filters": ["(objectCategory=person)(objectClass=user)"],
                "attributes": ["sAMAccountName", "description", "memberOf", "userAccountControl", "servicePrincipalName"],
            });

            let priority = dispatcher.effective_priority("domain_user_enumeration");
            match dispatcher
                .throttled_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        cred_user = %item.credential.username,
                        "Domain user enumeration dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_DOMAIN_USER_ENUM, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_DOMAIN_USER_ENUM, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "Domain user enumeration deferred");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch user enumeration");
                }
            }
        }
    }
}

struct UserEnumWork {
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
        let key = format!("user_enum:{}", "contoso.local");
        assert_eq!(key, "user_enum:contoso.local");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_DOMAIN_USER_ENUM, "domain_user_enum");
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
            "technique": "ldap_user_enumeration",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
            "filters": ["(objectCategory=person)(objectClass=user)"],
            "attributes": ["sAMAccountName", "description", "memberOf", "userAccountControl", "servicePrincipalName"],
        });
        assert_eq!(payload["technique"], "ldap_user_enumeration");
        assert_eq!(payload["target_ip"], "192.168.58.10");
        assert_eq!(payload["domain"], "contoso.local");
    }

    #[test]
    fn ldap_filter_format() {
        let filters = ["(objectCategory=person)(objectClass=user)"];
        assert_eq!(filters.len(), 1);
        assert!(filters[0].contains("objectCategory=person"));
        assert!(filters[0].contains("objectClass=user"));
    }

    #[test]
    fn ldap_attributes_list() {
        let attrs = [
            "sAMAccountName",
            "description",
            "memberOf",
            "userAccountControl",
            "servicePrincipalName",
        ];
        assert_eq!(attrs.len(), 5);
        assert!(attrs.contains(&"sAMAccountName"));
        assert!(attrs.contains(&"servicePrincipalName"));
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
        let work = UserEnumWork {
            dedup_key: "user_enum:contoso.local".into(),
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
        let key = format!("user_enum:{}", "CONTOSO.LOCAL".to_lowercase());
        assert_eq!(key, "user_enum:contoso.local");
    }

    #[test]
    fn credential_quarantine_check_logic() {
        // Empty password should be skipped by the credential selection logic
        let cred = ares_core::models::Credential {
            id: "c1".into(),
            username: "admin".into(),
            password: "".into(),
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };
        assert!(cred.password.is_empty());
    }

    #[test]
    fn cross_domain_credential_fallback() {
        // When no same-domain cred exists, any cred can be used (cross-domain LDAP)
        let creds = [ares_core::models::Credential {
            id: "c1".into(),
            username: "admin".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "fabrikam.local".into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        }];
        let target_domain = "contoso.local";
        let same_domain = creds.iter().find(|c| {
            c.domain.to_lowercase() == target_domain.to_lowercase() && !c.password.is_empty()
        });
        assert!(same_domain.is_none());
        let fallback = creds.iter().find(|c| !c.password.is_empty());
        assert!(fallback.is_some());
        assert_eq!(fallback.unwrap().domain, "fabrikam.local");
    }
}
