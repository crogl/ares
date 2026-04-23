//! auto_dacl_abuse -- direct ACL abuse for known attack paths.
//!
//! Unlike acl_chain_follow (which requires BloodHound to populate acl_chains),
//! this module proactively dispatches known ACL abuse techniques when:
//!   - A credential is available for a user known to have dangerous permissions
//!   - The target object exists in the domain
//!
//! Covers: ForceChangePassword, GenericWrite (targeted Kerberoast), WriteDacl,
//! WriteOwner, GenericAll. Each abuse type maps to a specific tool invocation
//! (e.g., net rpc password for ForceChangePassword, bloodyAD for GenericWrite).

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Dispatches ACL abuse when matching credentials + bloodhound paths exist.
/// Interval: 30s.
pub async fn auto_dacl_abuse(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        if !dispatcher.is_technique_allowed("dacl_abuse") {
            continue;
        }

        let work: Vec<DaclWork> = {
            let state = dispatcher.state.read().await;

            if state.credentials.is_empty() {
                continue;
            }

            let mut items = Vec::new();

            // Check discovered_vulnerabilities for ACL-related vulns
            // (populated by BloodHound analysis or recon agents)
            for vuln in state.discovered_vulnerabilities.values() {
                let vtype = vuln.vuln_type.to_lowercase();

                let is_acl_vuln = vtype.contains("forcechangepassword")
                    || vtype.contains("genericwrite")
                    || vtype.contains("writedacl")
                    || vtype.contains("writeowner")
                    || vtype.contains("genericall")
                    || vtype.contains("self_membership")
                    || vtype.contains("write_membership");

                if !is_acl_vuln {
                    continue;
                }

                if state.exploited_vulnerabilities.contains(&vuln.vuln_id) {
                    continue;
                }

                let dedup_key = format!("dacl:{}", vuln.vuln_id);
                if state.is_processed(DEDUP_DACL_ABUSE, &dedup_key) {
                    continue;
                }

                // Extract source user from vuln details
                let source_user = vuln
                    .details
                    .get("source")
                    .or_else(|| vuln.details.get("source_user"))
                    .or_else(|| vuln.details.get("from"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let source_domain = vuln
                    .details
                    .get("source_domain")
                    .or_else(|| vuln.details.get("domain"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                if source_user.is_empty() {
                    continue;
                }

                // Find matching credential
                let cred = state
                    .credentials
                    .iter()
                    .find(|c| {
                        c.username.to_lowercase() == source_user.to_lowercase()
                            && (source_domain.is_empty()
                                || c.domain.to_lowercase() == source_domain.to_lowercase())
                    })
                    .cloned();

                if let Some(cred) = cred {
                    let target_user = vuln
                        .details
                        .get("target")
                        .or_else(|| vuln.details.get("target_user"))
                        .or_else(|| vuln.details.get("to"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();

                    let dc_ip = state
                        .domain_controllers
                        .get(&cred.domain.to_lowercase())
                        .cloned()
                        .unwrap_or_default();

                    items.push(DaclWork {
                        dedup_key,
                        vuln_id: vuln.vuln_id.clone(),
                        vuln_type: vtype,
                        source_user: source_user.to_string(),
                        target_user,
                        domain: cred.domain.clone(),
                        dc_ip,
                        credential: cred,
                    });
                }
            }

            items
        };

        for item in work {
            let payload = json!({
                "technique": "dacl_abuse",
                "acl_type": item.vuln_type,
                "vuln_id": item.vuln_id,
                "source_user": item.source_user,
                "target_user": item.target_user,
                "target_ip": item.dc_ip,
                "domain": item.domain,
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
            });

            let priority = dispatcher.effective_priority("dacl_abuse");
            match dispatcher
                .throttled_submit("acl_chain_step", "acl", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        vuln_id = %item.vuln_id,
                        acl_type = %item.vuln_type,
                        source = %item.source_user,
                        target = %item.target_user,
                        "DACL abuse dispatched"
                    );
                    {
                        let mut state = dispatcher.state.write().await;
                        state.mark_processed(DEDUP_DACL_ABUSE, item.dedup_key.clone());
                    }
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_DACL_ABUSE, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(vuln_id = %item.vuln_id, "DACL abuse deferred");
                }
                Err(e) => {
                    warn!(err = %e, vuln_id = %item.vuln_id, "Failed to dispatch DACL abuse");
                }
            }
        }
    }
}

struct DaclWork {
    dedup_key: String,
    vuln_id: String,
    vuln_type: String,
    source_user: String,
    target_user: String,
    domain: String,
    dc_ip: String,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_key_format() {
        let key = format!("dacl:{}", "vuln-acl-001");
        assert_eq!(key, "dacl:vuln-acl-001");
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_DACL_ABUSE, "dacl_abuse");
    }
}
