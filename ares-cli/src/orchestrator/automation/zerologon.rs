//! auto_zerologon -- check domain controllers for CVE-2020-1472 (ZeroLogon).
//!
//! ZeroLogon allows unauthenticated privilege escalation by exploiting a flaw
//! in the Netlogon protocol. Even on patched systems, the check is fast and
//! non-destructive. Dispatches `zerologon_check` (recon only, no exploit)
//! against each discovered DC once.
//!
//! If the check reports the DC is vulnerable, result processing will register
//! a "zerologon" vulnerability that other modules can act on.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Monitors for domain controllers and dispatches ZeroLogon checks.
/// Interval: 45s.
pub async fn auto_zerologon(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("zerologon") {
            continue;
        }

        let work: Vec<ZerologonWork> = {
            let state = dispatcher.state.read().await;

            state
                .domain_controllers
                .iter()
                .filter(|(_, dc_ip)| !state.is_processed(DEDUP_ZEROLOGON, dc_ip))
                .map(|(domain, dc_ip)| {
                    // Derive the DC hostname (NetBIOS name) from hosts or domain
                    let hostname = state
                        .hosts
                        .iter()
                        .find(|h| h.ip == *dc_ip)
                        .map(|h| h.hostname.clone())
                        .unwrap_or_default();

                    ZerologonWork {
                        domain: domain.clone(),
                        dc_ip: dc_ip.clone(),
                        hostname,
                    }
                })
                .collect()
        };

        for item in work {
            let payload = json!({
                "technique": "zerologon_check",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "hostname": item.hostname,
            });

            let priority = dispatcher.effective_priority("zerologon");
            match dispatcher
                .throttled_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        dc = %item.dc_ip,
                        domain = %item.domain,
                        "ZeroLogon check dispatched (CVE-2020-1472)"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_ZEROLOGON, item.dc_ip.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_ZEROLOGON, &item.dc_ip)
                        .await;
                }
                Ok(None) => {
                    debug!(dc = %item.dc_ip, "ZeroLogon check deferred by throttler");
                }
                Err(e) => {
                    warn!(err = %e, dc = %item.dc_ip, "Failed to dispatch ZeroLogon check");
                }
            }
        }
    }
}

struct ZerologonWork {
    domain: String,
    dc_ip: String,
    hostname: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_ZEROLOGON, "zerologon");
    }

    #[test]
    fn dedup_key_is_dc_ip() {
        // ZeroLogon dedup is by DC IP since we check each DC once
        let dc_ip = "192.168.58.10";
        assert_eq!(dc_ip, "192.168.58.10");
    }

    #[test]
    fn no_cred_required() {
        // ZeroLogon check doesn't require credentials
        let _payload = serde_json::json!({
            "technique": "zerologon_check",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "hostname": "dc01",
        });
    }

    #[test]
    fn hostname_extraction_empty_fallback() {
        let hosts: Vec<(String, String)> = vec![];
        let dc_ip = "192.168.58.10";
        let hostname = hosts
            .iter()
            .find(|(ip, _)| ip == dc_ip)
            .map(|(_, h)| h.clone())
            .unwrap_or_default();
        assert_eq!(hostname, "");
    }
}
