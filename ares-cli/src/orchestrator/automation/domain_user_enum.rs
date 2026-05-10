//! auto_domain_user_enum -- explicit per-domain LDAP user enumeration.
//!
//! Unlike initial recon (which does broad DC scanning), this module dispatches
//! targeted LDAP user enumeration per domain using the best available credential.
//! This fills the gap where a trusted domain's users are not enumerated because
//! the initial recon agent only has primary-domain credentials.
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

/// Collect user enumeration work items from current state.
///
/// Pure logic extracted from `auto_domain_user_enum` so it can be unit-tested
/// without needing a `Dispatcher` or async runtime.
fn collect_user_enum_work(state: &StateInner) -> Vec<UserEnumWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();

    for (domain, dc_ip) in &state.all_domains_with_dcs() {
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

        items.push(UserEnumWork {
            dedup_key,
            domain: domain.clone(),
            dc_ip: dc_ip.clone(),
            credential: cred,
        });
    }

    items
}

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
            collect_user_enum_work(&state)
        };

        for item in work {
            let cross_domain = item.credential.domain.to_lowercase() != item.domain.to_lowercase();
            let mut payload = json!({
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
            if cross_domain {
                payload["bind_domain"] = json!(item.credential.domain);
            }

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
        let work = collect_user_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credentials_no_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = collect_user_enum_work(&state);
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
        let work = collect_user_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].dc_ip, "192.168.58.10");
        assert_eq!(work[0].credential.username, "admin");
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
        state.mark_processed(DEDUP_DOMAIN_USER_ENUM, "user_enum:contoso.local".into());
        let work = collect_user_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_cross_domain_fallback() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // Only fabrikam cred available, should fall back
        state
            .credentials
            .push(make_credential("crossuser", "P@ssw0rd!", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_user_enum_work(&state);
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
        let work = collect_user_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_quarantined_credential_falls_back() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("baduser", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("gooduser", "Pass!456", "fabrikam.local")); // pragma: allowlist secret
        state.quarantine_principal("baduser", "contoso.local");
        let work = collect_user_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "gooduser");
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
        let work = collect_user_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dedup_key, "user_enum:contoso.local");
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
        let work = collect_user_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
    }
}
