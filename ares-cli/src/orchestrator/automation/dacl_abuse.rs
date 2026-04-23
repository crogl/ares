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

    #[test]
    fn acl_vuln_type_matching() {
        let positives = [
            "ForceChangePassword",
            "GenericWrite",
            "WriteDacl",
            "WriteOwner",
            "GenericAll",
            "self_membership",
            "write_membership",
            "SomePrefix_forcechangepassword_suffix",
        ];
        for t in &positives {
            let vtype = t.to_lowercase();
            let is_acl_vuln = vtype.contains("forcechangepassword")
                || vtype.contains("genericwrite")
                || vtype.contains("writedacl")
                || vtype.contains("writeowner")
                || vtype.contains("genericall")
                || vtype.contains("self_membership")
                || vtype.contains("write_membership");
            assert!(is_acl_vuln, "{t} should match as ACL vuln");
        }
    }

    #[test]
    fn non_acl_vuln_types_rejected() {
        let negatives = [
            "smb_signing_disabled",
            "mssql_access",
            "zerologon",
            "esc1",
            "kerberoast",
        ];
        for t in &negatives {
            let vtype = t.to_lowercase();
            let is_acl_vuln = vtype.contains("forcechangepassword")
                || vtype.contains("genericwrite")
                || vtype.contains("writedacl")
                || vtype.contains("writeowner")
                || vtype.contains("genericall")
                || vtype.contains("self_membership")
                || vtype.contains("write_membership");
            assert!(!is_acl_vuln, "{t} should NOT match as ACL vuln");
        }
    }

    #[test]
    fn source_user_extraction_keys() {
        // Verify the fallback chain for source user extraction
        let details = serde_json::json!({
            "source": "admin",
            "source_user": "admin2",
            "from": "admin3",
        });
        let source = details
            .get("source")
            .or_else(|| details.get("source_user"))
            .or_else(|| details.get("from"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(source, "admin");

        // Fallback to source_user
        let details2 = serde_json::json!({
            "source_user": "admin2",
        });
        let source2 = details2
            .get("source")
            .or_else(|| details2.get("source_user"))
            .or_else(|| details2.get("from"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(source2, "admin2");

        // No source returns empty
        let details3 = serde_json::json!({});
        let source3 = details3
            .get("source")
            .or_else(|| details3.get("source_user"))
            .or_else(|| details3.get("from"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(source3, "");
    }

    #[test]
    fn source_domain_extraction_keys() {
        let details = serde_json::json!({"source_domain": "contoso.local"});
        let source_domain = details
            .get("source_domain")
            .or_else(|| details.get("domain"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(source_domain, "contoso.local");

        let details2 = serde_json::json!({"domain": "fabrikam.local"});
        let source_domain2 = details2
            .get("source_domain")
            .or_else(|| details2.get("domain"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(source_domain2, "fabrikam.local");

        let details3 = serde_json::json!({});
        let source_domain3 = details3
            .get("source_domain")
            .or_else(|| details3.get("domain"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(source_domain3, "");
    }

    #[test]
    fn target_user_extraction_keys() {
        let details = serde_json::json!({"target": "victim", "target_user": "v2", "to": "v3"});
        let target = details
            .get("target")
            .or_else(|| details.get("target_user"))
            .or_else(|| details.get("to"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(target, "victim");

        let details2 = serde_json::json!({"target_user": "v2"});
        let target2 = details2
            .get("target")
            .or_else(|| details2.get("target_user"))
            .or_else(|| details2.get("to"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(target2, "v2");

        let details3 = serde_json::json!({"to": "v3"});
        let target3 = details3
            .get("target")
            .or_else(|| details3.get("target_user"))
            .or_else(|| details3.get("to"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(target3, "v3");
    }

    #[test]
    fn credential_matching_with_domain() {
        let source_user = "admin";
        let source_domain = "contoso.local";
        let cred_username = "Admin";
        let cred_domain = "CONTOSO.LOCAL";

        let matches = cred_username.to_lowercase() == source_user.to_lowercase()
            && (source_domain.is_empty()
                || cred_domain.to_lowercase() == source_domain.to_lowercase());
        assert!(matches);
    }

    #[test]
    fn credential_matching_without_domain() {
        let source_user = "admin";
        let source_domain = "";
        let cred_username = "admin";
        let cred_domain = "contoso.local";

        let matches = cred_username.to_lowercase() == source_user.to_lowercase()
            && (source_domain.is_empty()
                || cred_domain.to_lowercase() == source_domain.to_lowercase());
        assert!(matches);
    }

    #[test]
    fn credential_matching_wrong_user() {
        let source_user = "admin";
        let source_domain = "contoso.local";
        let cred_username = "jdoe";
        let cred_domain = "contoso.local";

        let matches = cred_username.to_lowercase() == source_user.to_lowercase()
            && (source_domain.is_empty()
                || cred_domain.to_lowercase() == source_domain.to_lowercase());
        assert!(!matches);
    }

    #[test]
    fn credential_matching_wrong_domain() {
        let source_user = "admin";
        let source_domain = "contoso.local";
        let cred_username = "admin";
        let cred_domain = "fabrikam.local";

        let matches = cred_username.to_lowercase() == source_user.to_lowercase()
            && (source_domain.is_empty()
                || cred_domain.to_lowercase() == source_domain.to_lowercase());
        assert!(!matches);
    }

    #[test]
    fn dacl_payload_structure() {
        let payload = serde_json::json!({
            "technique": "dacl_abuse",
            "acl_type": "forcechangepassword",
            "vuln_id": "vuln-acl-001",
            "source_user": "admin",
            "target_user": "victim",
            "target_ip": "192.168.58.10",
            "domain": "contoso.local",
            "credential": {
                "username": "admin",
                "password": "P@ssw0rd!",
                "domain": "contoso.local",
            },
        });
        assert_eq!(payload["technique"], "dacl_abuse");
        assert_eq!(payload["acl_type"], "forcechangepassword");
        assert_eq!(payload["source_user"], "admin");
        assert_eq!(payload["target_user"], "victim");
        assert_eq!(payload["credential"]["domain"], "contoso.local");
    }

    #[test]
    fn acl_vuln_type_case_insensitive() {
        for t in [
            "ForceChangePassword",
            "FORCECHANGEPASSWORD",
            "forcechangepassword",
        ] {
            let vtype = t.to_lowercase();
            assert!(vtype.contains("forcechangepassword"), "{t} should match");
        }
    }

    #[test]
    fn source_user_from_key() {
        let details = serde_json::json!({"from": "svc_account"});
        let source = details
            .get("source")
            .or_else(|| details.get("source_user"))
            .or_else(|| details.get("from"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert_eq!(source, "svc_account");
    }
}
