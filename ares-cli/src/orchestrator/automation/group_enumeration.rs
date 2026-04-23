//! auto_group_enumeration -- enumerate domain groups and memberships via LDAP.
//!
//! Dispatches per-domain LDAP group enumeration to discover security groups,
//! their members, and cross-domain memberships. This covers a large gap in
//! attack surface mapping — group membership determines ACL attack paths,
//! privilege escalation chains, and cross-domain lateral movement.
//!
//! The recon agent queries `(objectCategory=group)` and resolves membership
//! recursively, including Foreign Security Principals for cross-domain groups.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Collect group enumeration work items from current state.
///
/// Pure logic extracted from `auto_group_enumeration` so it can be unit-tested
/// without needing a `Dispatcher` or async runtime.
fn collect_group_enum_work(state: &StateInner) -> Vec<GroupEnumWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();

    for (domain, dc_ip) in &state.domain_controllers {
        let dedup_key = format!("group_enum:{}", domain.to_lowercase());
        if state.is_processed(DEDUP_GROUP_ENUMERATION, &dedup_key) {
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

        items.push(GroupEnumWork {
            dedup_key,
            domain: domain.clone(),
            dc_ip: dc_ip.clone(),
            credential: cred,
        });
    }

    items
}

/// Dispatches group enumeration per domain.
/// Interval: 45s.
pub async fn auto_group_enumeration(
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

        if !dispatcher.is_technique_allowed("group_enumeration") {
            continue;
        }

        let work: Vec<GroupEnumWork> = {
            let state = dispatcher.state.read().await;
            collect_group_enum_work(&state)
        };

        for item in work {
            let payload = json!({
                "technique": "ldap_group_enumeration",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
                "filters": ["(objectCategory=group)"],
                "attributes": [
                    "sAMAccountName", "member", "memberOf", "managedBy",
                    "groupType", "objectSid", "description", "cn"
                ],
                "enumerate_members": true,
                "resolve_foreign_principals": true,
                "instructions": concat!(
                    "Enumerate ALL security groups in this domain via LDAP query ",
                    "(objectCategory=group). For each group, resolve its members ",
                    "recursively, including Foreign Security Principals (CN=ForeignSecurityPrincipals). ",
                    "Report: group name, group type (Global/DomainLocal/Universal), ",
                    "all members (including nested), managedBy, and any cross-domain memberships. ",
                    "Use net group /domain or LDAP to enumerate. Also check Domain Local groups ",
                    "for foreign members from trusted domains. ",
                    "Pay special attention to groups that grant elevated privileges: ",
                    "Domain Admins, Enterprise Admins, Administrators, Backup Operators, ",
                    "Server Operators, Account Operators, DnsAdmins, and any custom groups ",
                    "with adminCount=1. Report all discovered users as discovered_users with ",
                    "their group memberships in the memberOf field."
                ),
            });

            let priority = dispatcher.effective_priority("group_enumeration");
            match dispatcher
                .throttled_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        "Group enumeration dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_GROUP_ENUMERATION, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_GROUP_ENUMERATION, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "Group enumeration deferred");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch group enumeration");
                }
            }
        }
    }
}

struct GroupEnumWork {
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
        let key = format!("group_enum:{}", "contoso.local");
        assert_eq!(key, "group_enum:contoso.local");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_GROUP_ENUMERATION, "group_enumeration");
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
            "technique": "ldap_group_enumeration",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
            "filters": ["(objectCategory=group)"],
            "attributes": [
                "sAMAccountName", "member", "memberOf", "managedBy",
                "groupType", "objectSid", "description", "cn"
            ],
            "enumerate_members": true,
            "resolve_foreign_principals": true,
        });
        assert_eq!(payload["technique"], "ldap_group_enumeration");
        assert_eq!(payload["target_ip"], "192.168.58.10");
        assert!(payload["enumerate_members"].as_bool().unwrap());
        assert!(payload["resolve_foreign_principals"].as_bool().unwrap());
    }

    #[test]
    fn ldap_attributes_list() {
        let attrs = [
            "sAMAccountName",
            "member",
            "memberOf",
            "managedBy",
            "groupType",
            "objectSid",
            "description",
            "cn",
        ];
        assert_eq!(attrs.len(), 8);
        assert!(attrs.contains(&"sAMAccountName"));
        assert!(attrs.contains(&"objectSid"));
        assert!(attrs.contains(&"managedBy"));
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
        let work = GroupEnumWork {
            dedup_key: "group_enum:contoso.local".into(),
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
        let key = format!("group_enum:{}", "CONTOSO.LOCAL".to_lowercase());
        assert_eq!(key, "group_enum:contoso.local");
    }

    #[test]
    fn dedup_keys_differ_per_domain() {
        let key1 = format!("group_enum:{}", "contoso.local");
        let key2 = format!("group_enum:{}", "fabrikam.local");
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
        let work = collect_group_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credentials_no_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = collect_group_enum_work(&state);
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
        let work = collect_group_enum_work(&state);
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
        state.mark_processed(DEDUP_GROUP_ENUMERATION, "group_enum:contoso.local".into());
        let work = collect_group_enum_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_cross_domain_fallback_to_first() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // Only fabrikam cred, should fall back to first()
        state
            .credentials
            .push(make_credential("crossuser", "P@ssw0rd!", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_group_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "crossuser");
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
            .push(make_credential("fadmin", "Pass!456", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_group_enum_work(&state);
        assert_eq!(work.len(), 2);
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
        let work = collect_group_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dedup_key, "group_enum:contoso.local");
    }

    #[test]
    fn collect_prefers_same_domain_cred() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("crossuser", "Cross!1", "fabrikam.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("localadmin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_group_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "localadmin");
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
        let work = collect_group_enum_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
    }
}
