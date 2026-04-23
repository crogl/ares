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

            if state.credentials.is_empty() {
                continue;
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
                    "a vulnerability with vuln_type matching the ACE type (e.g., 'forcechangepassword'), ",
                    "source user, target object, and domain. Focus on ACEs where the source is ",
                    "a user we have credentials for."
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
}
