//! auto_spooler_check -- detect Print Spooler service on discovered hosts.
//!
//! The Print Spooler service (MS-RPRN) is a common coercion vector: if running,
//! PrinterBug (SpoolSample) can force the machine to authenticate to an attacker
//! listener. It's also a prerequisite for PrintNightmare (CVE-2021-1675).
//!
//! This is a recon bridge: it dispatches a check per host and registers
//! `spooler_enabled` vulnerabilities that downstream coercion/CVE modules target.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Checks discovered hosts for Print Spooler service availability.
/// Interval: 45s.
pub async fn auto_spooler_check(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("spooler_check") {
            continue;
        }

        let work: Vec<SpoolerWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() {
                continue;
            }

            let mut items = Vec::new();

            for host in &state.hosts {
                let dedup_key = format!("spooler:{}", host.ip);
                if state.is_processed(DEDUP_SPOOLER_CHECK, &dedup_key) {
                    continue;
                }

                let domain = host
                    .hostname
                    .find('.')
                    .map(|i| host.hostname[i + 1..].to_lowercase())
                    .unwrap_or_default();

                let cred = state
                    .credentials
                    .iter()
                    .find(|c| !domain.is_empty() && c.domain.to_lowercase() == domain)
                    .or_else(|| state.credentials.first())
                    .cloned();

                let cred = match cred {
                    Some(c) => c,
                    None => continue,
                };

                items.push(SpoolerWork {
                    dedup_key,
                    target_ip: host.ip.clone(),
                    hostname: host.hostname.clone(),
                    domain,
                    credential: cred,
                });
            }

            items
        };

        for item in work {
            let payload = json!({
                "technique": "spooler_check",
                "target_ip": item.target_ip,
                "hostname": item.hostname,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("spooler_check");
            match dispatcher
                .throttled_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        target = %item.target_ip,
                        hostname = %item.hostname,
                        "Print Spooler check dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_SPOOLER_CHECK, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SPOOLER_CHECK, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(target = %item.target_ip, "Spooler check deferred");
                }
                Err(e) => {
                    warn!(err = %e, target = %item.target_ip, "Failed to dispatch spooler check");
                }
            }
        }
    }
}

struct SpoolerWork {
    dedup_key: String,
    target_ip: String,
    hostname: String,
    domain: String,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key = format!("spooler:{}", "192.168.58.22");
        assert_eq!(key, "spooler:192.168.58.22");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_SPOOLER_CHECK, "spooler_check");
    }

    #[test]
    fn domain_from_hostname() {
        let hostname = "srv01.contoso.local";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "contoso.local");
    }
}
