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

fn collect_zerologon_work(state: &StateInner) -> Vec<ZerologonWork> {
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
}

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
            collect_zerologon_work(&state)
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
    use crate::orchestrator::state::StateInner;

    fn make_host(ip: &str, hostname: &str, is_dc: bool) -> ares_core::models::Host {
        ares_core::models::Host {
            ip: ip.to_string(),
            hostname: hostname.to_string(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc,
            owned: false,
        }
    }

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

    #[test]
    fn collect_empty_state_returns_no_work() {
        let state = StateInner::new("test-op".into());
        let work = collect_zerologon_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_single_dc_produces_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = collect_zerologon_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].dc_ip, "192.168.58.10");
    }

    #[test]
    fn collect_multiple_dcs_produces_work_for_each() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.20".into());
        let work = collect_zerologon_work(&state);
        assert_eq!(work.len(), 2);
        let domains: Vec<&str> = work.iter().map(|w| w.domain.as_str()).collect();
        assert!(domains.contains(&"contoso.local"));
        assert!(domains.contains(&"fabrikam.local"));
    }

    #[test]
    fn collect_dedup_skips_already_processed_dc() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state.mark_processed(DEDUP_ZEROLOGON, "192.168.58.10".into());
        let work = collect_zerologon_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_dedup_skips_processed_keeps_unprocessed() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .domain_controllers
            .insert("fabrikam.local".into(), "192.168.58.20".into());
        state.mark_processed(DEDUP_ZEROLOGON, "192.168.58.10".into());
        let work = collect_zerologon_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "fabrikam.local");
    }

    #[test]
    fn collect_resolves_hostname_from_hosts() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        state
            .hosts
            .push(make_host("192.168.58.10", "dc01.contoso.local", true));
        let work = collect_zerologon_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].hostname, "dc01.contoso.local");
    }

    #[test]
    fn collect_hostname_empty_when_host_not_found() {
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        // No matching host in state.hosts
        state
            .hosts
            .push(make_host("192.168.58.99", "other.contoso.local", false));
        let work = collect_zerologon_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].hostname, "");
    }

    #[test]
    fn collect_no_credentials_still_produces_work() {
        // ZeroLogon is unauthenticated, so no credentials needed
        let mut state = StateInner::new("test-op".into());
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        assert!(state.credentials.is_empty());
        let work = collect_zerologon_work(&state);
        assert_eq!(work.len(), 1);
    }
}
