//! auto_smb_signing_detection -- bridge recon host data to VulnerabilityInfo.
//!
//! The SMB banner parser (`hosts.rs`) detects `(signing:True)` to mark DCs but
//! does NOT create VulnerabilityInfo objects for hosts with signing disabled.
//! This module scans `state.hosts` for non-DC hosts (signing:False is the default
//! for member servers) and publishes `smb_signing_disabled` vulns, which the
//! `ntlm_relay` module consumes to dispatch relay attacks.
//!
//! Pattern: mirrors `auto_mssql_detection` — scan host list, publish vulns.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::orchestrator::dispatcher::Dispatcher;

/// Scans discovered hosts for SMB signing disabled (non-DC Windows hosts).
/// DCs enforce signing; member servers typically do not.
/// Interval: 30s.
pub async fn auto_smb_signing_detection(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if !dispatcher.is_technique_allowed("smb_signing_disabled") {
            continue;
        }

        let work: Vec<(String, String, String)> = {
            let state = dispatcher.state.read().await;

            state
                .hosts
                .iter()
                .filter(|h| {
                    // Non-DC hosts with SMB (port 445) likely have signing disabled.
                    // DCs enforce signing:True; member servers default to signing not required.
                    !h.is_dc
                        && !h.hostname.is_empty()
                        && !state
                            .discovered_vulnerabilities
                            .contains_key(&format!("smb_signing_{}", h.ip.replace('.', "_")))
                })
                .map(|h| {
                    let domain = h
                        .hostname
                        .find('.')
                        .map(|i| h.hostname[i + 1..].to_lowercase())
                        .unwrap_or_default();
                    (h.ip.clone(), h.hostname.clone(), domain)
                })
                .collect()
        };

        for (ip, hostname, domain) in work {
            let vuln = ares_core::models::VulnerabilityInfo {
                vuln_id: format!("smb_signing_{}", ip.replace('.', "_")),
                vuln_type: "smb_signing_disabled".to_string(),
                target: ip.clone(),
                discovered_by: "auto_smb_signing_detection".to_string(),
                discovered_at: chrono::Utc::now(),
                details: {
                    let mut d = std::collections::HashMap::new();
                    d.insert("target_ip".to_string(), json!(ip));
                    d.insert("ip".to_string(), json!(ip));
                    if !hostname.is_empty() {
                        d.insert("hostname".to_string(), json!(hostname));
                    }
                    if !domain.is_empty() {
                        d.insert("domain".to_string(), json!(domain));
                    }
                    d
                },
                recommended_agent: "coercion".to_string(),
                priority: dispatcher.effective_priority("smb_signing_disabled"),
            };

            match dispatcher
                .state
                .publish_vulnerability_with_strategy(
                    &dispatcher.queue,
                    vuln,
                    Some(&dispatcher.config.strategy),
                )
                .await
            {
                Ok(true) => {
                    info!(ip = %ip, hostname = %hostname, "SMB signing disabled — vulnerability queued for relay");
                }
                Ok(false) => {} // already exists
                Err(e) => warn!(err = %e, ip = %ip, "Failed to publish SMB signing vulnerability"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn vuln_id_format() {
        let ip = "192.168.58.22";
        let vuln_id = format!("smb_signing_{}", ip.replace('.', "_"));
        assert_eq!(vuln_id, "smb_signing_192_168_58_22");
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
