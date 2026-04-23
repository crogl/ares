//! auto_acl_discovery -- discover ACL attack paths via targeted LDAP queries.
//!
//! Bridges the gap between BloodHound collection and ACL exploitation.
//! BloodHound collects data, but the ACL chain analysis must be extracted
//! and registered as discovered_vulnerabilities for `auto_dacl_abuse` to
//! exploit.
//!
//! This module dispatches `ldap_acl_enumeration` tasks per domain to:
//!   1. Query nTSecurityDescriptor on user/group/computer objects
//!   2. Identify dangerous ACEs (GenericAll, WriteDacl, ForceChangePassword,
//!      GenericWrite, WriteOwner, Self-Membership)
//!   3. Register discovered ACL paths as vulnerabilities
//!
//! Interval: 60s (heavy LDAP query, don't run too frequently).

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// The dangerous ACE types we want the recon agent to identify.
const DANGEROUS_ACE_TYPES: &[&str] = &[
    "GenericAll",
    "GenericWrite",
    "WriteDacl",
    "WriteOwner",
    "ForceChangePassword",
    "Self-Membership",
    "WriteMember",
    "AllExtendedRights",
    "WriteProperty",
];

/// Collect ACL discovery work items from current state.
///
/// Pure logic extracted from `auto_acl_discovery` so it can be unit-tested
/// without needing a `Dispatcher` or async runtime.
fn collect_acl_discovery_work(state: &StateInner) -> Vec<AclDiscoveryWork> {
    if state.credentials.is_empty() {
        return Vec::new();
    }

    let mut items = Vec::new();

    for (domain, dc_ip) in &state.domain_controllers {
        let dedup_key = format!("acl_disc:{}", domain.to_lowercase());
        if state.is_processed(DEDUP_ACL_DISCOVERY, &dedup_key) {
            continue;
        }

        // Prefer same-domain credential, fall back to any available.
        let cred = state
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
            })
            .cloned();

        let cred = match cred {
            Some(c) => c,
            None => continue,
        };

        // Collect known users in this domain to check ACEs against.
        let domain_users: Vec<String> = state
            .credentials
            .iter()
            .filter(|c| c.domain.to_lowercase() == domain.to_lowercase())
            .map(|c| c.username.clone())
            .collect();

        items.push(AclDiscoveryWork {
            dedup_key,
            domain: domain.clone(),
            dc_ip: dc_ip.clone(),
            credential: cred,
            known_users: domain_users,
        });
    }

    items
}

/// Dispatches LDAP ACE enumeration per domain to discover ACL attack paths.
/// Only runs after BloodHound collection has been dispatched (to avoid
/// duplicating effort).
pub async fn auto_acl_discovery(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Wait for initial recon + BloodHound to run first.
    tokio::time::sleep(Duration::from_secs(90)).await;

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if !dispatcher.is_technique_allowed("acl_discovery") {
            continue;
        }

        let work: Vec<AclDiscoveryWork> = {
            let state = dispatcher.state.read().await;
            collect_acl_discovery_work(&state)
        };

        for item in work {
            let payload = json!({
                "technique": "ldap_acl_enumeration",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
                "ace_types": DANGEROUS_ACE_TYPES,
                "known_users": item.known_users,
                "instructions": concat!(
                    "Enumerate ACL attack paths in this domain using dacledit.py or ",
                    "bloodyAD to query DACLs on user/group/computer objects. ",
                    "For each dangerous ACE found (GenericAll, WriteDacl, ForceChangePassword, ",
                    "GenericWrite, WriteOwner, Self-Membership on users/groups), register it as ",
                    "a vulnerability with EXACTLY these fields:\n",
                    "  vuln_type: lowercase ACE type (e.g. 'forcechangepassword', 'genericall', ",
                    "'genericwrite', 'writedacl', 'writeowner', 'self_membership')\n",
                    "  source: the user/group that HAS the permission (attacker)\n",
                    "  target: the user/group/computer that is the TARGET of the permission (victim)\n",
                    "  target_type: 'User', 'Group', or 'Computer' (object class of target)\n",
                    "  domain: the domain where this ACE exists\n",
                    "  source_domain: the domain of the source principal\n",
                    "Focus on ACEs where the source is a user we have credentials for. ",
                    "For GenericAll/GenericWrite on Computer objects, also set target_type='Computer' ",
                    "to enable RBCD exploitation. Check both inbound and outbound ACEs."
                ),
            });

            let priority = dispatcher.effective_priority("acl_discovery");
            match dispatcher
                .throttled_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        known_users = item.known_users.len(),
                        "ACL discovery dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_ACL_DISCOVERY, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_ACL_DISCOVERY, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "ACL discovery deferred");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch ACL discovery");
                }
            }
        }
    }
}

struct AclDiscoveryWork {
    dedup_key: String,
    domain: String,
    dc_ip: String,
    credential: ares_core::models::Credential,
    known_users: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::state::StateInner;
    use ares_core::models::Credential;

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

    #[test]
    fn dedup_key_format() {
        let key = format!("acl_disc:{}", "contoso.local");
        assert_eq!(key, "acl_disc:contoso.local");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_ACL_DISCOVERY, "acl_discovery");
    }

    #[test]
    fn dangerous_ace_types_not_empty() {
        assert!(!DANGEROUS_ACE_TYPES.is_empty());
    }

    #[test]
    fn dangerous_ace_types_contains_key_types() {
        assert!(DANGEROUS_ACE_TYPES.contains(&"GenericAll"));
        assert!(DANGEROUS_ACE_TYPES.contains(&"WriteDacl"));
        assert!(DANGEROUS_ACE_TYPES.contains(&"ForceChangePassword"));
        assert!(DANGEROUS_ACE_TYPES.contains(&"GenericWrite"));
        assert!(DANGEROUS_ACE_TYPES.contains(&"WriteOwner"));
        assert!(DANGEROUS_ACE_TYPES.contains(&"Self-Membership"));
    }

    #[test]
    fn dangerous_ace_types_count() {
        assert_eq!(DANGEROUS_ACE_TYPES.len(), 9);
    }

    #[test]
    fn dangerous_ace_types_includes_write_property() {
        assert!(DANGEROUS_ACE_TYPES.contains(&"WriteProperty"));
        assert!(DANGEROUS_ACE_TYPES.contains(&"AllExtendedRights"));
        assert!(DANGEROUS_ACE_TYPES.contains(&"WriteMember"));
    }

    #[test]
    fn dangerous_ace_types_no_duplicates() {
        let mut seen = std::collections::HashSet::new();
        for ace in DANGEROUS_ACE_TYPES {
            assert!(seen.insert(*ace), "Duplicate ACE type: {ace}");
        }
    }

    #[test]
    fn dedup_key_case_normalized() {
        let key1 = format!("acl_disc:{}", "CONTOSO.LOCAL".to_lowercase());
        let key2 = format!("acl_disc:{}", "contoso.local");
        assert_eq!(key1, key2);
    }

    #[test]
    fn acl_discovery_payload_structure() {
        let payload = serde_json::json!({
            "technique": "ldap_acl_enumeration",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {
                "username": "admin",
                "password": "P@ssw0rd!",
                "domain": "contoso.local",
            },
            "ace_types": DANGEROUS_ACE_TYPES,
            "known_users": ["admin", "jdoe"],
        });
        assert_eq!(payload["technique"], "ldap_acl_enumeration");
        assert_eq!(payload["target_ip"], "192.168.58.10");
        let ace_types = payload["ace_types"].as_array().unwrap();
        assert_eq!(ace_types.len(), 9);
    }

    #[test]
    fn credential_domain_preference() {
        // Same-domain credential is preferred
        let domain = "contoso.local";
        let cred_same = "contoso.local";
        let cred_other = "fabrikam.local";
        assert_eq!(cred_same.to_lowercase(), domain.to_lowercase());
        assert_ne!(cred_other.to_lowercase(), domain.to_lowercase());
    }

    #[test]
    fn known_users_collection() {
        let credentials = [
            ("admin", "contoso.local"),
            ("jdoe", "contoso.local"),
            ("admin", "fabrikam.local"),
        ];
        let domain = "contoso.local";
        let domain_users: Vec<&str> = credentials
            .iter()
            .filter(|(_, d)| d.to_lowercase() == domain.to_lowercase())
            .map(|(u, _)| *u)
            .collect();
        assert_eq!(domain_users.len(), 2);
        assert!(domain_users.contains(&"admin"));
        assert!(domain_users.contains(&"jdoe"));
    }

    #[test]
    fn acl_discovery_work_fields() {
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
        let work = AclDiscoveryWork {
            dedup_key: "acl_disc:contoso.local".into(),
            domain: "contoso.local".into(),
            dc_ip: "192.168.58.10".into(),
            credential: cred,
            known_users: vec!["admin".into(), "jdoe".into()],
        };
        assert_eq!(work.known_users.len(), 2);
        assert_eq!(work.domain, "contoso.local");
    }

    // --- collect_acl_discovery_work tests ---

    #[test]
    fn collect_empty_state_returns_no_work() {
        let state = StateInner::new("test-op".into());
        let work = collect_acl_discovery_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credentials_returns_no_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = collect_acl_discovery_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_domain_controllers_returns_no_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_acl_discovery_work(&state);
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
        let work = collect_acl_discovery_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].dc_ip, "192.168.58.10");
        assert_eq!(work[0].dedup_key, "acl_disc:contoso.local");
        assert_eq!(work[0].credential.username, "admin");
        assert_eq!(work[0].credential.domain, "contoso.local");
        assert!(work[0].known_users.contains(&"admin".to_string()));
    }

    #[test]
    fn collect_multiple_domains_produces_work_for_each() {
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
        let work = collect_acl_discovery_work(&state);
        assert_eq!(work.len(), 2);
        let domains: Vec<&str> = work.iter().map(|w| w.domain.as_str()).collect();
        assert!(domains.contains(&"contoso.local"));
        assert!(domains.contains(&"fabrikam.local"));
    }

    #[test]
    fn collect_dedup_skips_already_processed_domain() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.mark_processed(DEDUP_ACL_DISCOVERY, "acl_disc:contoso.local".into());
        let work = collect_acl_discovery_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_dedup_skips_processed_but_keeps_unprocessed() {
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
        state.mark_processed(DEDUP_ACL_DISCOVERY, "acl_disc:contoso.local".into());
        let work = collect_acl_discovery_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "fabrikam.local");
    }

    #[test]
    fn collect_prefers_same_domain_credential() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // Add cross-domain cred first, then same-domain cred
        state
            .credentials
            .push(make_credential("crossuser", "Cross!1", "fabrikam.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_acl_discovery_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "admin");
        assert_eq!(work[0].credential.domain, "contoso.local");
    }

    #[test]
    fn collect_falls_back_to_cross_domain_credential() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // Only a fabrikam credential available for contoso DC
        state
            .credentials
            .push(make_credential("crossuser", "Cross!1", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_acl_discovery_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "crossuser");
        assert_eq!(work[0].credential.domain, "fabrikam.local");
    }

    #[test]
    fn collect_skips_empty_password_credentials() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // Credential with empty password
        state
            .credentials
            .push(make_credential("admin", "", "contoso.local"));
        let work = collect_acl_discovery_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_skips_empty_password_uses_next() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("nopw", "", "contoso.local"));
        state
            .credentials
            .push(make_credential("haspw", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_acl_discovery_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "haspw");
    }

    #[test]
    fn collect_known_users_only_from_same_domain() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("jdoe", "Pass!456", "contoso.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("crossuser", "Cross!1", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_acl_discovery_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].known_users.len(), 2);
        assert!(work[0].known_users.contains(&"admin".to_string()));
        assert!(work[0].known_users.contains(&"jdoe".to_string()));
        assert!(!work[0].known_users.contains(&"crossuser".to_string()));
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
        let work = collect_acl_discovery_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dedup_key, "acl_disc:contoso.local");
    }

    #[test]
    fn collect_all_empty_password_creds_skips_domain() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("user1", "", "contoso.local"));
        state
            .credentials
            .push(make_credential("user2", "", "fabrikam.local"));
        let work = collect_acl_discovery_work(&state);
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
        let work = collect_acl_discovery_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_quarantined_same_domain_falls_back_to_cross_domain() {
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
        state.quarantine_credential("baduser", "contoso.local");
        let work = collect_acl_discovery_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].credential.username, "gooduser");
    }

    #[test]
    fn collect_all_credentials_quarantined_skips_domain() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("user1", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("user2", "Pass!456", "fabrikam.local")); // pragma: allowlist secret
        state.quarantine_credential("user1", "contoso.local");
        state.quarantine_credential("user2", "fabrikam.local");
        let work = collect_acl_discovery_work(&state);
        assert!(work.is_empty());
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
        let work = collect_acl_discovery_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
    }

    #[test]
    fn collect_case_insensitive_domain_matching_for_creds() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("CONTOSO.LOCAL".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "Contoso.Local")); // pragma: allowlist secret
        let work = collect_acl_discovery_work(&state);
        assert_eq!(work.len(), 1);
        // Should match via case-insensitive comparison
        assert_eq!(work[0].credential.username, "admin");
        assert_eq!(work[0].credential.domain, "Contoso.Local");
    }

    #[test]
    fn collect_known_users_includes_empty_password_users() {
        // known_users collects ALL creds for the domain, even ones with empty passwords
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("nopw_user", "", "contoso.local"));
        let work = collect_acl_discovery_work(&state);
        assert_eq!(work.len(), 1);
        // Both users should appear in known_users (useful for ACE checking)
        assert_eq!(work[0].known_users.len(), 2);
        assert!(work[0].known_users.contains(&"admin".to_string()));
        assert!(work[0].known_users.contains(&"nopw_user".to_string()));
    }
}
