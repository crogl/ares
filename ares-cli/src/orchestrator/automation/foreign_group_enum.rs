//! auto_foreign_group_enum -- enumerate cross-domain/cross-forest group memberships.
//!
//! Discovers foreign security principals (FSPs) — users/groups from one domain
//! that are members of groups in another domain. This reveals cross-forest and
//! cross-domain attack paths that BloodHound's intra-domain analysis might miss.
//!
//! Dispatches LDAP queries per trust relationship to find:
//! - Foreign users in local groups (e.g., essos\daenerys in sevenkingdoms\AcrossTheNarrowSea)
//! - Foreign groups nested in local groups
//! - Domain Local groups with foreign members (the primary FSP container)

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Enumerate cross-domain foreign group memberships.
/// Interval: 45s.
pub async fn auto_foreign_group_enum(
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

        if !dispatcher.is_technique_allowed("foreign_group_enum") {
            continue;
        }

        let work: Vec<ForeignGroupWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() || state.domains.len() < 2 {
                continue;
            }

            let mut items = Vec::new();

            // For each domain, enumerate foreign security principals
            for domain in &state.domains {
                let dedup_key = format!("foreign_group:{domain}");
                if state.is_processed(DEDUP_FOREIGN_GROUP_ENUM, &dedup_key) {
                    continue;
                }

                let dc_ip = match state.domain_controllers.get(domain) {
                    Some(ip) => ip.clone(),
                    None => continue,
                };

                // Find a credential for this domain
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

                items.push(ForeignGroupWork {
                    dedup_key,
                    domain: domain.clone(),
                    dc_ip,
                    credential: cred,
                });
            }

            items
        };

        for item in work {
            let payload = json!({
                "technique": "foreign_group_enumeration",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("foreign_group_enum");
            match dispatcher
                .throttled_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        "Foreign group enumeration dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_FOREIGN_GROUP_ENUM, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_FOREIGN_GROUP_ENUM, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "Foreign group enum deferred");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch foreign group enum");
                }
            }
        }
    }
}

struct ForeignGroupWork {
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
        let key = format!("foreign_group:{}", "contoso.local");
        assert_eq!(key, "foreign_group:contoso.local");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_FOREIGN_GROUP_ENUM, "foreign_group_enum");
    }

    #[test]
    fn requires_multiple_domains() {
        let domains: Vec<String> = vec!["contoso.local".to_string()];
        assert!(
            domains.len() < 2,
            "Single domain should skip foreign group enum"
        );
    }
}
