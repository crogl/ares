//! auto_webdav_detection -- detect WebDAV on hosts for NTLM relay.
//!
//! Hosts running WebClient service (WebDAV) accept HTTP-based NTLM auth,
//! which bypasses SMB signing requirements. This enables relay attacks
//! (HTTP→LDAP/SMB) even when SMB signing is enforced. WebDAV is commonly
//! enabled on IIS servers and member servers with WebClient service.
//!
//! This is a bridge module (like smb_signing.rs): it checks discovered hosts
//! for WebDAV indicators and registers `webdav_enabled` vulnerabilities
//! that downstream modules (ntlm_relay) can target.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Checks discovered hosts for WebDAV service and registers vulnerabilities.
/// Interval: 45s.
pub async fn auto_webdav_detection(
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

        if !dispatcher.is_technique_allowed("webdav_detection") {
            continue;
        }

        let work: Vec<WebDavWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() {
                continue;
            }

            let mut items = Vec::new();

            for host in &state.hosts {
                // Skip DCs (WebDAV relay is for member servers)
                if host.is_dc {
                    continue;
                }

                // Check if host has WebDAV indicators in services
                let has_webdav = host.services.iter().any(|s| {
                    let sl = s.to_lowercase();
                    sl.contains("webdav")
                        || sl.contains("webclient")
                        || sl.contains("iis")
                        || (sl.contains("80/") && sl.contains("http"))
                });

                if !has_webdav {
                    continue;
                }

                let dedup_key = format!("webdav:{}", host.ip);
                if state.is_processed(DEDUP_WEBDAV_DETECTION, &dedup_key) {
                    continue;
                }

                // Check if vuln already registered
                let vuln_id = format!("webdav_enabled_{}", host.ip.replace('.', "_"));
                if state.discovered_vulnerabilities.contains_key(&vuln_id) {
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

                items.push(WebDavWork {
                    dedup_key,
                    vuln_id,
                    target_ip: host.ip.clone(),
                    hostname: host.hostname.clone(),
                    domain,
                    credential: cred,
                });
            }

            items
        };

        for item in work {
            // Dispatch a recon task to verify WebDAV is accessible
            let payload = json!({
                "technique": "webdav_check",
                "target_ip": item.target_ip,
                "hostname": item.hostname,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("webdav_detection");
            match dispatcher
                .throttled_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        target = %item.target_ip,
                        hostname = %item.hostname,
                        "WebDAV detection check dispatched"
                    );

                    // Also register the vuln proactively (service tag is strong signal)
                    let vuln = ares_core::models::VulnerabilityInfo {
                        vuln_id: item.vuln_id,
                        vuln_type: "webdav_enabled".to_string(),
                        target: item.target_ip.clone(),
                        discovered_by: "auto_webdav_detection".to_string(),
                        discovered_at: chrono::Utc::now(),
                        details: {
                            let mut d = std::collections::HashMap::new();
                            d.insert(
                                "hostname".to_string(),
                                serde_json::Value::String(item.hostname.clone()),
                            );
                            d.insert(
                                "domain".to_string(),
                                serde_json::Value::String(item.domain.clone()),
                            );
                            d.insert(
                                "target_ip".to_string(),
                                serde_json::Value::String(item.target_ip.clone()),
                            );
                            d
                        },
                        recommended_agent: "coercion".to_string(),
                        priority: 4,
                    };

                    let _ = dispatcher
                        .state
                        .publish_vulnerability_with_strategy(
                            &dispatcher.queue,
                            vuln,
                            Some(&dispatcher.config.strategy),
                        )
                        .await;

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_WEBDAV_DETECTION, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_WEBDAV_DETECTION, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(target = %item.target_ip, "WebDAV detection deferred");
                }
                Err(e) => {
                    warn!(err = %e, target = %item.target_ip, "Failed to dispatch WebDAV detection");
                }
            }
        }
    }
}

struct WebDavWork {
    dedup_key: String,
    vuln_id: String,
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
        let key = format!("webdav:{}", "192.168.58.22");
        assert_eq!(key, "webdav:192.168.58.22");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_WEBDAV_DETECTION, "webdav_detection");
    }

    #[test]
    fn webdav_service_detection_webdav() {
        let services = ["80/tcp webdav".to_string()];
        let has_webdav = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("webdav")
                || sl.contains("webclient")
                || sl.contains("iis")
                || (sl.contains("80/") && sl.contains("http"))
        });
        assert!(has_webdav);
    }

    #[test]
    fn webdav_service_detection_iis() {
        let services = ["80/tcp iis httpd".to_string()];
        let has_webdav = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("webdav")
                || sl.contains("webclient")
                || sl.contains("iis")
                || (sl.contains("80/") && sl.contains("http"))
        });
        assert!(has_webdav);
    }

    #[test]
    fn webdav_service_detection_http() {
        let services = ["80/tcp http".to_string()];
        let has_webdav = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("webdav")
                || sl.contains("webclient")
                || sl.contains("iis")
                || (sl.contains("80/") && sl.contains("http"))
        });
        assert!(has_webdav);
    }

    #[test]
    fn no_webdav_service() {
        let services = [
            "445/tcp microsoft-ds".to_string(),
            "3389/tcp ms-wbt-server".to_string(),
        ];
        let has_webdav = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("webdav")
                || sl.contains("webclient")
                || sl.contains("iis")
                || (sl.contains("80/") && sl.contains("http"))
        });
        assert!(!has_webdav);
    }

    #[test]
    fn vuln_id_format() {
        let ip = "192.168.58.22";
        let vuln_id = format!("webdav_enabled_{}", ip.replace('.', "_"));
        assert_eq!(vuln_id, "webdav_enabled_192_168_58_22");
    }

    #[test]
    fn domain_from_hostname() {
        let hostname = "web01.contoso.local";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "contoso.local");
    }

    #[test]
    fn webdav_service_detection_webclient() {
        let services = ["WebClient service running".to_string()];
        let has_webdav = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("webdav")
                || sl.contains("webclient")
                || sl.contains("iis")
                || (sl.contains("80/") && sl.contains("http"))
        });
        assert!(has_webdav);
    }

    #[test]
    fn webdav_service_detection_case_insensitive() {
        let services = ["80/TCP WEBDAV".to_string()];
        let has_webdav = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("webdav")
                || sl.contains("webclient")
                || sl.contains("iis")
                || (sl.contains("80/") && sl.contains("http"))
        });
        assert!(has_webdav);
    }

    #[test]
    fn webdav_service_not_port_80_without_http() {
        // Port 80 alone without "http" keyword should not match
        let services = ["80/tcp other_service".to_string()];
        let has_webdav = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("webdav")
                || sl.contains("webclient")
                || sl.contains("iis")
                || (sl.contains("80/") && sl.contains("http"))
        });
        assert!(!has_webdav);
    }

    #[test]
    fn domain_from_hostname_bare() {
        let hostname = "web01";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "");
    }

    #[test]
    fn domain_from_hostname_subdomain() {
        let hostname = "web01.child.contoso.local";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "child.contoso.local");
    }

    #[test]
    fn vuln_id_format_various_ips() {
        let ips = ["192.168.58.10", "192.168.58.22", "192.168.58.240"];
        for ip in ips {
            let vuln_id = format!("webdav_enabled_{}", ip.replace('.', "_"));
            assert!(vuln_id.starts_with("webdav_enabled_"));
            assert!(!vuln_id.contains('.'));
        }
    }

    #[test]
    fn credential_domain_matching() {
        let domain = "contoso.local".to_string();
        let cred_domain = "CONTOSO.LOCAL";
        assert_eq!(cred_domain.to_lowercase(), domain);
    }

    #[test]
    fn credential_domain_matching_empty_domain() {
        let domain = "".to_string();
        let cred_domain = "contoso.local";
        // When domain is empty, the first branch should fail and fall through
        let matches = !domain.is_empty() && cred_domain.to_lowercase() == domain;
        assert!(!matches);
    }

    #[test]
    fn webdav_vuln_details_construction() {
        let hostname = "web01.contoso.local".to_string();
        let domain = "contoso.local".to_string();
        let target_ip = "192.168.58.22".to_string();
        let mut d = std::collections::HashMap::new();
        d.insert(
            "hostname".to_string(),
            serde_json::Value::String(hostname.clone()),
        );
        d.insert(
            "domain".to_string(),
            serde_json::Value::String(domain.clone()),
        );
        d.insert(
            "target_ip".to_string(),
            serde_json::Value::String(target_ip.clone()),
        );
        assert_eq!(d.len(), 3);
        assert_eq!(d["hostname"], serde_json::json!("web01.contoso.local"));
        assert_eq!(d["domain"], serde_json::json!("contoso.local"));
        assert_eq!(d["target_ip"], serde_json::json!("192.168.58.22"));
    }

    #[test]
    fn webdav_payload_structure() {
        let payload = serde_json::json!({
            "technique": "webdav_check",
            "target_ip": "192.168.58.22",
            "hostname": "web01.contoso.local",
            "domain": "contoso.local",
            "credential": {
                "username": "admin",
                "password": "P@ssw0rd!",
                "domain": "contoso.local",
            },
        });
        assert_eq!(payload["technique"], "webdav_check");
        assert_eq!(payload["target_ip"], "192.168.58.22");
        assert_eq!(payload["hostname"], "web01.contoso.local");
        assert_eq!(payload["credential"]["username"], "admin");
    }

    #[test]
    fn empty_services_no_webdav() {
        let services: Vec<String> = vec![];
        let has_webdav = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("webdav")
                || sl.contains("webclient")
                || sl.contains("iis")
                || (sl.contains("80/") && sl.contains("http"))
        });
        assert!(!has_webdav);
    }
}
