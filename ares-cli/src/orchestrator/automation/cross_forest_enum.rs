//! auto_cross_forest_enum -- targeted cross-forest enumeration.
//!
//! When we have Admin Pwn3d on a DC in a foreign forest but haven't enumerated
//! that forest's users/groups, this module dispatches targeted LDAP enumeration
//! using the best available credential path.
//!
//! Unlike `auto_domain_user_enum` (which fires once per domain), this module
//! retries with better credentials as they become available — specifically:
//!   - Cracked passwords from cross-forest secretsdump hashes
//!   - Credentials obtained via MSSQL linked server pivots
//!   - Admin credentials from owned DCs in the foreign forest
//!
//! This covers the gap where essos.local users are not enumerated because
//! initial recon only has north/sevenkingdoms creds.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Check if a credential belongs to a different forest than the target domain.
fn is_cross_forest(cred_domain: &str, target_domain: &str) -> bool {
    let c = cred_domain.to_lowercase();
    let t = target_domain.to_lowercase();
    // Same domain or parent/child = same forest
    !(c == t || c.ends_with(&format!(".{t}")) || t.ends_with(&format!(".{c}")))
}

/// Build dedup key incorporating the credential to allow retry with better creds.
fn cross_forest_dedup_key(domain: &str, username: &str, cred_domain: &str) -> String {
    format!(
        "xforest:{}:{}@{}",
        domain.to_lowercase(),
        username.to_lowercase(),
        cred_domain.to_lowercase()
    )
}

/// Dispatches targeted user + group enumeration for foreign forests.
/// Interval: 45s.
pub async fn auto_cross_forest_enum(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(45));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Wait for initial credential discovery and cross-domain pivots.
    tokio::time::sleep(Duration::from_secs(120)).await;

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if !dispatcher.is_technique_allowed("cross_forest_enum") {
            continue;
        }

        let work: Vec<CrossForestWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() || state.domains.len() < 2 {
                continue;
            }

            let mut items = Vec::new();

            for (domain, dc_ip) in &state.domain_controllers {
                let domain_lower = domain.to_lowercase();

                // Count how many users we know in this domain.
                let known_user_count = state
                    .credentials
                    .iter()
                    .filter(|c| c.domain.to_lowercase() == domain_lower)
                    .count();

                // Also count hashes for this domain.
                let known_hash_count = state
                    .hashes
                    .iter()
                    .filter(|h| h.domain.to_lowercase() == domain_lower)
                    .count();

                // Skip domains where we already have good coverage
                // (at least 5 credentials or 10 hashes = likely already enumerated).
                if known_user_count >= 5 || known_hash_count >= 10 {
                    continue;
                }

                // Find the best credential for this domain.
                // Priority: same-domain cred > admin cred > cracked hash > any cred.
                let best_cred = state
                    .credentials
                    .iter()
                    .filter(|c| {
                        !c.password.is_empty()
                            && !state.is_credential_quarantined(&c.username, &c.domain)
                    })
                    .min_by_key(|c| {
                        let c_dom = c.domain.to_lowercase();
                        if c_dom == domain_lower {
                            0 // Same domain = best
                        } else if c.is_admin {
                            1 // Admin from another domain = good (trust auth)
                        } else if !is_cross_forest(&c_dom, &domain_lower) {
                            2 // Same forest = acceptable
                        } else {
                            3 // Cross-forest = may work via trust
                        }
                    })
                    .cloned();

                let cred = match best_cred {
                    Some(c) => c,
                    None => continue,
                };

                let dedup_key = cross_forest_dedup_key(&domain_lower, &cred.username, &cred.domain);
                if state.is_processed(DEDUP_CROSS_FOREST_ENUM, &dedup_key) {
                    continue;
                }

                items.push(CrossForestWork {
                    dedup_key,
                    domain: domain.clone(),
                    dc_ip: dc_ip.clone(),
                    credential: cred,
                    is_under_enumerated: known_user_count < 3,
                });
            }

            items
        };

        for item in work {
            // Dispatch user enumeration
            let user_payload = json!({
                "technique": "ldap_user_enumeration",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
                "filters": ["(objectCategory=person)(objectClass=user)"],
                "attributes": [
                    "sAMAccountName", "description", "memberOf",
                    "userAccountControl", "servicePrincipalName",
                    "msDS-AllowedToDelegateTo", "adminCount"
                ],
                "cross_forest": true,
                "instructions": concat!(
                    "This is a cross-forest enumeration task. Enumerate ALL users in the ",
                    "target domain via LDAP. If the credential is from a different domain, ",
                    "authenticate via the forest trust. Report every user found with their ",
                    "group memberships, SPNs, delegation settings, and description fields. ",
                    "Pay special attention to accounts with adminCount=1, ",
                    "DoesNotRequirePreAuth, or interesting SPNs."
                ),
            });

            let priority = dispatcher.effective_priority("cross_forest_enum");
            match dispatcher
                .throttled_submit("recon", "recon", user_payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        cred_user = %item.credential.username,
                        cred_domain = %item.credential.domain,
                        under_enumerated = item.is_under_enumerated,
                        "Cross-forest user enumeration dispatched"
                    );
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "Cross-forest user enum deferred");
                    continue; // Don't mark as processed if deferred
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch cross-forest user enum");
                    continue;
                }
            }

            // Also dispatch group enumeration for the same domain
            let group_payload = json!({
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
                    "groupType", "objectSid", "description"
                ],
                "enumerate_members": true,
                "resolve_foreign_principals": true,
                "cross_forest": true,
                "instructions": concat!(
                    "Enumerate ALL security groups in this domain and their members. ",
                    "Resolve Foreign Security Principals to their source domain. ",
                    "Report group name, type (Global/DomainLocal/Universal), members, ",
                    "and managed-by. This is critical for mapping cross-domain attack paths."
                ),
            });

            let group_priority = dispatcher.effective_priority("group_enumeration");
            if let Ok(Some(task_id)) = dispatcher
                .throttled_submit("recon", "recon", group_payload, group_priority)
                .await
            {
                info!(
                    task_id = %task_id,
                    domain = %item.domain,
                    "Cross-forest group enumeration dispatched"
                );
            }

            // Mark as processed
            dispatcher
                .state
                .write()
                .await
                .mark_processed(DEDUP_CROSS_FOREST_ENUM, item.dedup_key.clone());
            let _ = dispatcher
                .state
                .persist_dedup(&dispatcher.queue, DEDUP_CROSS_FOREST_ENUM, &item.dedup_key)
                .await;
        }
    }
}

struct CrossForestWork {
    dedup_key: String,
    domain: String,
    dc_ip: String,
    credential: ares_core::models::Credential,
    is_under_enumerated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_cross_forest_same_domain() {
        assert!(!is_cross_forest("contoso.local", "contoso.local"));
    }

    #[test]
    fn is_cross_forest_child_domain() {
        assert!(!is_cross_forest("child.contoso.local", "contoso.local"));
    }

    #[test]
    fn is_cross_forest_parent_domain() {
        assert!(!is_cross_forest("contoso.local", "child.contoso.local"));
    }

    #[test]
    fn is_cross_forest_different_forests() {
        assert!(is_cross_forest("contoso.local", "fabrikam.local"));
    }

    #[test]
    fn is_cross_forest_case_insensitive() {
        assert!(!is_cross_forest("CONTOSO.LOCAL", "contoso.local"));
        assert!(is_cross_forest("CONTOSO.LOCAL", "fabrikam.local"));
    }

    #[test]
    fn dedup_key_format() {
        let key = cross_forest_dedup_key("fabrikam.local", "Admin", "CONTOSO.LOCAL");
        assert_eq!(key, "xforest:fabrikam.local:admin@contoso.local");
    }

    #[test]
    fn dedup_key_case_insensitive() {
        let k1 = cross_forest_dedup_key("FABRIKAM.LOCAL", "Admin", "contoso.local");
        let k2 = cross_forest_dedup_key("fabrikam.local", "admin", "CONTOSO.LOCAL");
        assert_eq!(k1, k2);
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_CROSS_FOREST_ENUM, "cross_forest_enum");
    }
}
