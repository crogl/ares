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
use crate::orchestrator::state::StateInner;

/// Work item for SMB signing detection.
struct SmbSigningWork {
    ip: String,
    hostname: String,
    domain: String,
}

fn collect_smb_signing_work(state: &StateInner) -> Vec<SmbSigningWork> {
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
            SmbSigningWork {
                ip: h.ip.clone(),
                hostname: h.hostname.clone(),
                domain,
            }
        })
        .collect()
}

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

        let work = {
            let state = dispatcher.state.read().await;
            collect_smb_signing_work(&state)
        };

        for item in work {
            let vuln = ares_core::models::VulnerabilityInfo {
                vuln_id: format!("smb_signing_{}", item.ip.replace('.', "_")),
                vuln_type: "smb_signing_disabled".to_string(),
                target: item.ip.clone(),
                discovered_by: "auto_smb_signing_detection".to_string(),
                discovered_at: chrono::Utc::now(),
                details: {
                    let mut d = std::collections::HashMap::new();
                    d.insert("target_ip".to_string(), json!(item.ip));
                    d.insert("ip".to_string(), json!(item.ip));
                    if !item.hostname.is_empty() {
                        d.insert("hostname".to_string(), json!(item.hostname));
                    }
                    if !item.domain.is_empty() {
                        d.insert("domain".to_string(), json!(item.domain));
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
                    info!(ip = %item.ip, hostname = %item.hostname, "SMB signing disabled — vulnerability queued for relay");
                }
                Ok(false) => {} // already exists
                Err(e) => {
                    warn!(err = %e, ip = %item.ip, "Failed to publish SMB signing vulnerability")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn collect_empty_state_returns_no_work() {
        let state = StateInner::new("test-op".into());
        let work = collect_smb_signing_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_non_dc_host_produces_work() {
        let mut state = StateInner::new("test-op".into());
        state
            .hosts
            .push(make_host("192.168.58.22", "srv01.contoso.local", false));
        let work = collect_smb_signing_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].ip, "192.168.58.22");
        assert_eq!(work[0].hostname, "srv01.contoso.local");
        assert_eq!(work[0].domain, "contoso.local");
    }

    #[test]
    fn collect_dc_host_skipped() {
        let mut state = StateInner::new("test-op".into());
        state
            .hosts
            .push(make_host("192.168.58.10", "dc01.contoso.local", true));
        let work = collect_smb_signing_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_empty_hostname_skipped() {
        let mut state = StateInner::new("test-op".into());
        state.hosts.push(make_host("192.168.58.22", "", false));
        let work = collect_smb_signing_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_already_discovered_vuln_skipped() {
        let mut state = StateInner::new("test-op".into());
        state
            .hosts
            .push(make_host("192.168.58.22", "srv01.contoso.local", false));
        // Simulate existing vulnerability
        state.discovered_vulnerabilities.insert(
            "smb_signing_192_168_58_22".into(),
            ares_core::models::VulnerabilityInfo {
                vuln_id: "smb_signing_192_168_58_22".into(),
                vuln_type: "smb_signing_disabled".into(),
                target: "192.168.58.22".into(),
                discovered_by: "test".into(),
                discovered_at: chrono::Utc::now(),
                details: std::collections::HashMap::new(),
                recommended_agent: "coercion".into(),
                priority: 5,
            },
        );
        let work = collect_smb_signing_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_multiple_hosts_mixed_dc_and_member() {
        let mut state = StateInner::new("test-op".into());
        state
            .hosts
            .push(make_host("192.168.58.10", "dc01.contoso.local", true));
        state
            .hosts
            .push(make_host("192.168.58.22", "srv01.contoso.local", false));
        state
            .hosts
            .push(make_host("192.168.58.23", "srv02.contoso.local", false));
        let work = collect_smb_signing_work(&state);
        assert_eq!(work.len(), 2);
        let ips: Vec<&str> = work.iter().map(|w| w.ip.as_str()).collect();
        assert!(ips.contains(&"192.168.58.22"));
        assert!(ips.contains(&"192.168.58.23"));
        assert!(!ips.contains(&"192.168.58.10"));
    }

    #[test]
    fn collect_host_without_fqdn_gets_empty_domain() {
        let mut state = StateInner::new("test-op".into());
        state.hosts.push(make_host("192.168.58.22", "srv01", false));
        let work = collect_smb_signing_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].domain, "");
    }

    #[test]
    fn collect_skips_vuln_keeps_clean() {
        let mut state = StateInner::new("test-op".into());
        state
            .hosts
            .push(make_host("192.168.58.22", "srv01.contoso.local", false));
        state
            .hosts
            .push(make_host("192.168.58.23", "srv02.contoso.local", false));
        // Only 192.168.58.22 has existing vuln
        state.discovered_vulnerabilities.insert(
            "smb_signing_192_168_58_22".into(),
            ares_core::models::VulnerabilityInfo {
                vuln_id: "smb_signing_192_168_58_22".into(),
                vuln_type: "smb_signing_disabled".into(),
                target: "192.168.58.22".into(),
                discovered_by: "test".into(),
                discovered_at: chrono::Utc::now(),
                details: std::collections::HashMap::new(),
                recommended_agent: "coercion".into(),
                priority: 5,
            },
        );
        let work = collect_smb_signing_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].ip, "192.168.58.23");
    }
}
