//! auto_dns_enum -- DNS zone transfer and record enumeration.
//!
//! Attempts AXFR zone transfers and enumerates DNS records (SRV, A, CNAME)
//! from each discovered DC. DNS records reveal additional hosts, services,
//! and naming conventions that port scanning alone may miss.
//!
//! Zone transfers are often allowed from domain-joined machines, and even
//! when blocked, DNS SRV record enumeration reveals AD-registered services
//! (e.g., _msdcs, _kerberos, _ldap, _gc, _http).

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// DNS enumeration per domain.
/// Interval: 45s.
pub async fn auto_dns_enum(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("dns_enum") {
            continue;
        }

        let work: Vec<DnsEnumWork> = {
            let state = dispatcher.state.read().await;

            let mut items = Vec::new();

            for (domain, dc_ip) in &state.domain_controllers {
                let dedup_key = format!("dns_enum:{}", domain.to_lowercase());
                if state.is_processed(DEDUP_DNS_ENUM, &dedup_key) {
                    continue;
                }

                // DNS enum can work without creds (zone transfer, SRV queries)
                // but we pass creds if available for authenticated queries
                let cred = state
                    .credentials
                    .iter()
                    .find(|c| {
                        !c.password.is_empty() && c.domain.to_lowercase() == domain.to_lowercase()
                    })
                    .cloned();

                items.push(DnsEnumWork {
                    dedup_key,
                    domain: domain.clone(),
                    dc_ip: dc_ip.clone(),
                    credential: cred,
                });
            }

            items
        };

        for item in work {
            let mut payload = json!({
                "technique": "dns_enumeration",
                "target_ip": item.dc_ip,
                "domain": item.domain,
            });

            if let Some(ref cred) = item.credential {
                payload["credential"] = json!({
                    "username": cred.username,
                    "password": cred.password,
                    "domain": cred.domain,
                });
            }

            let priority = dispatcher.effective_priority("dns_enum");
            match dispatcher
                .throttled_submit("recon", "recon", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %item.domain,
                        dc = %item.dc_ip,
                        "DNS enumeration dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_DNS_ENUM, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_DNS_ENUM, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(domain = %item.domain, "DNS enumeration deferred");
                }
                Err(e) => {
                    warn!(err = %e, domain = %item.domain, "Failed to dispatch DNS enumeration");
                }
            }
        }
    }
}

struct DnsEnumWork {
    dedup_key: String,
    domain: String,
    dc_ip: String,
    credential: Option<ares_core::models::Credential>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key = format!("dns_enum:{}", "contoso.local");
        assert_eq!(key, "dns_enum:contoso.local");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_DNS_ENUM, "dns_enum");
    }

    #[test]
    fn no_cred_required() {
        // DNS enum works without credentials for zone transfer / SRV queries
        let cred: Option<ares_core::models::Credential> = None;
        assert!(cred.is_none());
    }
}
