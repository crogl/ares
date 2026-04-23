//! auto_smbclient_enum -- authenticated SMB share listing per domain.
//!
//! Complements auto_share_enumeration by using authenticated sessions to
//! discover shares that require credentials. Uses smbclient or netexec
//! to list shares on all known hosts.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Dispatches authenticated SMB share enumeration per host.
/// Interval: 45s.
pub async fn auto_smbclient_enum(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("smbclient_enum") {
            continue;
        }

        let work: Vec<SmbEnumWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() {
                continue;
            }

            let mut items = Vec::new();

            for host in &state.hosts {
                // Check if host has SMB
                let has_smb = host.services.iter().any(|s| {
                    let sl = s.to_lowercase();
                    sl.contains("445") || sl.contains("smb") || sl.contains("cifs")
                });
                if !has_smb {
                    continue;
                }

                let dedup_key = format!("smb_auth_enum:{}", host.ip);
                if state.is_processed(DEDUP_SMBCLIENT_ENUM, &dedup_key) {
                    continue;
                }

                // Infer domain from hostname
                let domain = host
                    .hostname
                    .find('.')
                    .map(|i| host.hostname[i + 1..].to_string())
                    .unwrap_or_default();

                // Pick a credential for this domain
                let cred = match state
                    .credentials
                    .iter()
                    .find(|c| {
                        !domain.is_empty()
                            && c.domain.to_lowercase() == domain.to_lowercase()
                            && !c.password.is_empty()
                            && !state.is_credential_quarantined(&c.username, &c.domain)
                    })
                    .or_else(|| {
                        state.credentials.iter().find(|c| {
                            !c.password.is_empty()
                                && !state.is_credential_quarantined(&c.username, &c.domain)
                        })
                    }) {
                    Some(c) => c.clone(),
                    None => continue,
                };

                items.push(SmbEnumWork {
                    dedup_key,
                    target_ip: host.ip.clone(),
                    hostname: host.hostname.clone(),
                    domain,
                    credential: cred,
                });
            }

            items
        };

        for item in work {
            let payload = json!({
                "technique": "authenticated_share_enumeration",
                "target_ip": item.target_ip,
                "hostname": item.hostname,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("smbclient_enum");
            match dispatcher
                .throttled_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        host = %item.target_ip,
                        "Authenticated SMB share enumeration dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_SMBCLIENT_ENUM, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SMBCLIENT_ENUM, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(host = %item.target_ip, "SMB auth enum deferred");
                }
                Err(e) => {
                    warn!(err = %e, host = %item.target_ip, "Failed to dispatch SMB auth enum");
                }
            }
        }
    }
}

struct SmbEnumWork {
    dedup_key: String,
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
        let key = format!("smb_auth_enum:{}", "192.168.58.10");
        assert_eq!(key, "smb_auth_enum:192.168.58.10");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_SMBCLIENT_ENUM, "smbclient_enum");
    }

    #[test]
    fn smb_service_detection() {
        let services = [
            "445/tcp microsoft-ds".to_string(),
            "80/tcp http".to_string(),
        ];
        let has_smb = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("445") || sl.contains("smb") || sl.contains("cifs")
        });
        assert!(has_smb);
    }

    #[test]
    fn smb_service_detection_by_name() {
        let services = ["microsoft-ds smb".to_string()];
        let has_smb = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("445") || sl.contains("smb") || sl.contains("cifs")
        });
        assert!(has_smb);
    }

    #[test]
    fn no_smb_service() {
        let services = [
            "3389/tcp ms-wbt-server".to_string(),
            "80/tcp http".to_string(),
        ];
        let has_smb = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("445") || sl.contains("smb") || sl.contains("cifs")
        });
        assert!(!has_smb);
    }

    #[test]
    fn domain_from_hostname_preserves_case() {
        // smbclient_enum uses to_string() not to_lowercase() for domain
        let hostname = "srv01.CONTOSO.LOCAL";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_string())
            .unwrap_or_default();
        assert_eq!(domain, "CONTOSO.LOCAL");
    }
}
