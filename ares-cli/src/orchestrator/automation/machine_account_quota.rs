//! auto_machine_account_quota -- check MachineAccountQuota (MAQ) per domain.
//!
//! The default MAQ of 10 allows any authenticated user to create computer
//! accounts. This is a prerequisite for noPac (CVE-2021-42287) and RBCD
//! attacks. If MAQ > 0, downstream modules can proceed with machine account
//! creation-based attacks.
//!
//! Dispatches a recon check per domain to query the ms-DS-MachineAccountQuota
//! attribute from the domain root.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Checks MAQ setting per domain via LDAP query.
/// Interval: 45s.
pub async fn auto_machine_account_quota(
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

        if !dispatcher.is_technique_allowed("machine_account_quota") {
            continue;
        }

        let work: Vec<MaqWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() {
                continue;
            }

            let mut items = Vec::new();

            for (domain, dc_ip) in &state.domain_controllers {
                let dedup_key = format!("maq:{}", domain.to_lowercase());
                if state.is_processed(DEDUP_MACHINE_ACCOUNT_QUOTA, &dedup_key) {
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

                items.push(MaqWork {
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
                "technique": "machine_account_quota_check",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("machine_account_quota");
            match dispatcher
                .throttled_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        "MachineAccountQuota check dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_MACHINE_ACCOUNT_QUOTA, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(
                            &dispatcher.queue,
                            DEDUP_MACHINE_ACCOUNT_QUOTA,
                            &item.dedup_key,
                        )
                        .await;
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "MAQ check deferred");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch MAQ check");
                }
            }
        }
    }
}

struct MaqWork {
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
        let key = format!("maq:{}", "contoso.local");
        assert_eq!(key, "maq:contoso.local");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_MACHINE_ACCOUNT_QUOTA, "machine_account_quota");
    }
}
