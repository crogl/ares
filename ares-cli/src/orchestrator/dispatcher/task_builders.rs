//! Convenience methods for common task types (request_crack, request_recon, etc.).

use anyhow::Result;
use serde_json::json;
use tracing::{debug, info};

use crate::orchestrator::state::{DEDUP_CROSS_REALM_LATERAL, DEDUP_SCANNED_TARGETS};

use super::Dispatcher;

impl Dispatcher {
    /// Submit a crack task for a hash.
    pub async fn request_crack(&self, hash: &ares_core::models::Hash) -> Result<Option<String>> {
        let payload = json!({
            "hash_type": hash.hash_type,
            "hash_value": hash.hash_value,
            "username": hash.username,
            "domain": hash.domain,
        });
        // Crack tasks are non-LLM, normal priority
        self.throttled_submit("crack", "cracker", payload, 5).await
    }

    /// Submit a recon task.
    ///
    /// Guards (mirroring Python's `request_recon` in `routing.py`):
    /// 1. Skip entirely if domain admin has been achieved
    /// 2. Skip nmap tasks if all targets are already in `scanned_targets`
    /// 3. Auto-dispatch nmap prerequisite before enumeration if targets not scanned
    pub async fn request_recon(
        &self,
        target_ip: &str,
        domain: &str,
        techniques: &[&str],
        credential: Option<&ares_core::models::Credential>,
    ) -> Result<Option<String>> {
        // Guard 1: Skip recon if domain admin already achieved
        {
            let state = self.state.read().await;
            if state.has_domain_admin {
                debug!(
                    target_ip = target_ip,
                    "Skipping recon — domain admin already achieved"
                );
                return Ok(None);
            }
        }

        let is_nmap = techniques.contains(&"network_scan") || techniques.contains(&"nmap_scan");
        let is_smb_signing = techniques.contains(&"smb_signing_check");
        let is_scan_only = (is_nmap || is_smb_signing)
            && techniques
                .iter()
                .all(|t| *t == "network_scan" || *t == "nmap_scan" || *t == "smb_signing_check");

        // Guard 2: Skip nmap/scan tasks if target already scanned
        if is_scan_only {
            let state = self.state.read().await;
            if state.is_processed(DEDUP_SCANNED_TARGETS, target_ip) {
                debug!(
                    target_ip = target_ip,
                    "Skipping scan — target already in scanned_targets"
                );
                return Ok(None);
            }
        }

        // Guard 3: Auto-dispatch nmap prerequisite before enumeration
        // If this is NOT a scan task and the target hasn't been scanned yet,
        // dispatch an nmap scan first at priority 1 (urgent).
        if !is_scan_only {
            let needs_scan = {
                let state = self.state.read().await;
                !state.is_processed(DEDUP_SCANNED_TARGETS, target_ip)
            };
            if needs_scan {
                info!(
                    target_ip = target_ip,
                    "Auto-dispatching nmap prerequisite before enumeration"
                );
                let scan_payload = json!({
                    "target_ip": target_ip,
                    "domain": domain,
                    "techniques": ["network_scan", "smb_signing_check"],
                });
                // Priority 1 = urgent, scanned before the enumeration task
                let _ = self
                    .throttled_submit("recon", "recon", scan_payload, 1)
                    .await;
            }
        }

        // Mark nmap targets as scanned (optimistic, to prevent duplicate dispatches)
        if is_nmap {
            {
                let mut state = self.state.write().await;
                state.mark_processed(DEDUP_SCANNED_TARGETS, target_ip.to_string());
            }
            // Persist to Redis so it survives restarts
            let _ = self
                .state
                .persist_dedup(&self.queue, DEDUP_SCANNED_TARGETS, target_ip)
                .await;
        }

        let mut payload = json!({
            "target_ip": target_ip,
            "domain": domain,
            "techniques": techniques,
        });
        if let Some(cred) = credential {
            payload["credential"] = json!({
                "username": cred.username,
                "password": cred.password,
                "domain": cred.domain,
            });
        }

        // Nmap tasks get priority 1, other recon priority 5
        let priority = if is_nmap { 1 } else { 5 };
        self.throttled_submit("recon", "recon", payload, priority)
            .await
    }

    /// Submit a low-hanging fruit credential discovery task (SYSVOL, GPP, LDAP, LAPS).
    ///
    /// Mirrors Python's fast credential discovery dispatch: sends multiple high-success-rate
    /// techniques in a single task so the LLM agent executes them sequentially.
    pub async fn request_low_hanging_fruit(
        &self,
        target_ip: &str,
        domain: &str,
        credential: &ares_core::models::Credential,
        priority: i32,
    ) -> Result<Option<String>> {
        let payload = json!({
            "techniques": [
                "sysvol_script_search",
                "gpp_password_finder",
                "ldap_search_descriptions",
                "laps_dump"
            ],
            "reason": "low_hanging_fruit",
            "target_ip": target_ip,
            "domain": domain,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("credential_access", "credential_access", payload, priority)
            .await
    }

    /// Submit a credential access task (kerberoast, asrep, secretsdump, etc.).
    pub async fn request_credential_access(
        &self,
        technique: &str,
        target_ip: &str,
        domain: &str,
        credential: &ares_core::models::Credential,
        priority: i32,
    ) -> Result<Option<String>> {
        let payload = json!({
            "technique": technique,
            "target_ip": target_ip,
            "domain": domain,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("credential_access", "credential_access", payload, priority)
            .await
    }

    /// Submit a secretsdump task.
    pub async fn request_secretsdump(
        &self,
        target_ip: &str,
        credential: &ares_core::models::Credential,
        priority: i32,
    ) -> Result<Option<String>> {
        let payload = json!({
            "technique": "secretsdump",
            "target_ip": target_ip,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("credential_access", "credential_access", payload, priority)
            .await
    }

    /// Submit a secretsdump task using NTLM hash (pass-the-hash).
    pub async fn request_secretsdump_hash(
        &self,
        target_ip: &str,
        username: &str,
        domain: &str,
        hash_value: &str,
        priority: i32,
    ) -> Result<Option<String>> {
        let payload = json!({
            "technique": "secretsdump",
            "target_ip": target_ip,
            "credential": {
                "username": username,
                "domain": domain,
            },
            "hash_value": hash_value,
        });
        self.throttled_submit("credential_access", "credential_access", payload, priority)
            .await
    }

    /// Submit a lateral movement task.
    ///
    /// Refuses to dispatch when the credential's realm differs from the target
    /// host's realm and no trust path is known — wrong-realm NTLM/Kerberos auth
    /// against a foreign DC just returns ACCESS_DENIED and burns LLM tokens
    /// (see the swarm of CHILD\dave → sql01.fabrikam.local failures).
    pub async fn request_lateral(
        &self,
        target_ip: &str,
        credential: &ares_core::models::Credential,
        technique: &str,
    ) -> Result<Option<String>> {
        // Stable key shared with the cross-realm guard below so a rejection
        // permanently suppresses retries from credential_expansion and the LLM.
        let cross_realm_key = format!(
            "{}|{}|{}|{}",
            credential.domain.to_lowercase(),
            credential.username.to_lowercase(),
            target_ip,
            technique
        );

        {
            let state = self.state.read().await;
            if state.is_processed(DEDUP_CROSS_REALM_LATERAL, &cross_realm_key) {
                debug!(
                    target_ip = target_ip,
                    cred_user = %credential.username,
                    technique = technique,
                    "Skipping lateral — already rejected as cross-realm dead-end"
                );
                return Ok(None);
            }
        }

        // Resolve target's realm from state.hosts (FQDN suffix).
        let target_domain = {
            let state = self.state.read().await;
            state
                .hosts
                .iter()
                .find(|h| h.ip == target_ip)
                .and_then(|h| h.hostname.split_once('.').map(|(_, d)| d.to_lowercase()))
        };
        if let Some(td) = target_domain {
            let cd = credential.domain.to_lowercase();
            if !cd.is_empty()
                && cd != td
                && !td.ends_with(&format!(".{cd}"))
                && !cd.ends_with(&format!(".{td}"))
            {
                tracing::warn!(
                    target_ip = %target_ip,
                    target_domain = %td,
                    cred_domain = %cd,
                    cred_user = %credential.username,
                    technique = %technique,
                    "Refusing cross-realm lateral movement — use forest_trust_escalation or get a same-realm credential first"
                );
                {
                    let mut state = self.state.write().await;
                    state.mark_processed(DEDUP_CROSS_REALM_LATERAL, cross_realm_key.clone());
                }
                let _ = self
                    .state
                    .persist_dedup(&self.queue, DEDUP_CROSS_REALM_LATERAL, &cross_realm_key)
                    .await;
                return Ok(None);
            }
        }
        let payload = json!({
            "technique": technique,
            "target_ip": target_ip,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("lateral_movement", "lateral", payload, 5)
            .await
    }

    /// Submit an exploit task for a vulnerability.
    ///
    /// Looks up the best available credential or hash for the vuln's target/domain
    /// and attaches it to the payload so the agent doesn't have to discover auth independently.
    pub async fn request_exploit(
        &self,
        vuln: &ares_core::models::VulnerabilityInfo,
        priority: i32,
    ) -> Result<Option<String>> {
        let mut payload = json!({
            "vuln_id": vuln.vuln_id,
            "vuln_type": vuln.vuln_type,
            "target": vuln.target,
            "details": vuln.details,
        });

        // Look up credentials for this exploit from state
        {
            let state = self.state.read().await;

            // Try account_name from vuln details first, then fall back to any cred for the target domain
            let account_name = vuln
                .details
                .get("account_name")
                .and_then(|v| v.as_str())
                .or_else(|| vuln.details.get("AccountName").and_then(|v| v.as_str()));

            let domain = vuln
                .details
                .get("domain")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            // Try to find a matching credential
            let cred = if let Some(acct) = account_name {
                state
                    .credentials
                    .iter()
                    .find(|c| c.username.to_lowercase() == acct.to_lowercase())
            } else {
                None
            }
            .or_else(|| {
                // Fall back to any non-delegation credential for the vuln's domain
                if !domain.is_empty() {
                    state.credentials.iter().find(|c| {
                        c.domain.to_lowercase() == domain.to_lowercase()
                            && !state.is_delegation_account(&c.username)
                    })
                } else {
                    // Fall back to first available non-delegation credential
                    state
                        .credentials
                        .iter()
                        .find(|c| !state.is_delegation_account(&c.username))
                }
            });

            if let Some(cred) = cred {
                payload["credential"] = json!({
                    "username": cred.username,
                    "password": cred.password,
                    "domain": cred.domain,
                });
            }

            // For MSSQL vulns, include ALL available credentials for the domain
            // so the LLM can try each one (different users have different MSSQL
            // permissions — e.g. sam.wilson can EXECUTE AS LOGIN = 'sa').
            if vuln.vuln_type.starts_with("mssql") && !domain.is_empty() {
                let all_creds: Vec<_> = state
                    .credentials
                    .iter()
                    .filter(|c| {
                        c.domain.to_lowercase() == domain.to_lowercase()
                            && !state.is_delegation_account(&c.username)
                    })
                    .map(|c| {
                        json!({
                            "username": c.username,
                            "password": c.password,
                            "domain": c.domain,
                        })
                    })
                    .collect();
                if all_creds.len() > 1 {
                    payload["all_credentials"] = json!(all_creds);
                }
            }

            // Also attach a hash if available for the account
            if let Some(acct) = account_name {
                if let Some(hash) = state
                    .hashes
                    .iter()
                    .find(|h| h.username.to_lowercase() == acct.to_lowercase())
                {
                    payload["hash"] = json!(hash.hash_value);
                    payload["hash_username"] = json!(hash.username);
                    if let Some(ref aes) = hash.aes_key {
                        payload["aes_key"] = json!(aes);
                    }
                }
            }
        }

        let role = if vuln.recommended_agent.is_empty() {
            "privesc"
        } else {
            &vuln.recommended_agent
        };
        self.throttled_submit("exploit", role, payload, priority)
            .await
    }

    /// Submit a BloodHound collection task.
    pub async fn request_bloodhound(
        &self,
        domain: &str,
        dc_ip: &str,
        credential: &ares_core::models::Credential,
    ) -> Result<Option<String>> {
        let payload = json!({
            "technique": "bloodhound_collect",
            "domain": domain,
            "target_ip": dc_ip,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("recon", "recon", payload, 7).await
    }

    /// Submit a share enumeration task against a host using credentials.
    pub async fn request_share_enumeration(
        &self,
        host_ip: &str,
        credential: &ares_core::models::Credential,
    ) -> Result<Option<String>> {
        let payload = json!({
            "techniques": ["enumerate_shares"],
            "target_ip": host_ip,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("recon", "recon", payload, 5).await
    }

    /// Submit a share spider task.
    pub async fn request_share_spider(
        &self,
        host_ip: &str,
        share_name: &str,
        credential: &ares_core::models::Credential,
    ) -> Result<Option<String>> {
        let payload = json!({
            "technique": "share_spider",
            "target_ip": host_ip,
            "share_name": share_name,
            "credential": {
                "username": credential.username,
                "password": credential.password,
                "domain": credential.domain,
            },
        });
        self.throttled_submit("credential_access", "credential_access", payload, 8)
            .await
    }

    /// Submit a coercion task.
    pub async fn request_coercion(
        &self,
        target_ip: &str,
        listener_ip: &str,
        techniques: &[&str],
    ) -> Result<Option<String>> {
        let payload = json!({
            "target_ip": target_ip,
            "listener_ip": listener_ip,
            "techniques": techniques,
        });
        self.throttled_submit("coercion", "coercion", payload, 3)
            .await
    }

    /// Submit a CERTIPY find task for ADCS enumeration.
    ///
    /// `ntlm_hash` and `hash_username` enable pass-the-hash authentication when
    /// no cleartext credential is available for the target domain.
    pub async fn request_certipy_find(
        &self,
        target_ip: &str,
        domain: &str,
        credential: &ares_core::models::Credential,
        ntlm_hash: Option<&str>,
        hash_username: Option<&str>,
        ca_host_ip: Option<&str>,
    ) -> Result<Option<String>> {
        // When PTH hash is available, use the hash user's identity for the target domain
        let (cred_user, cred_pass, cred_domain) = if let Some(_hash) = ntlm_hash {
            let user = hash_username.unwrap_or(&credential.username);
            (user.to_string(), String::new(), domain.to_string())
        } else {
            (
                credential.username.clone(),
                credential.password.clone(),
                credential.domain.clone(),
            )
        };

        let mut payload = json!({
            "technique": "certipy_find",
            "target_ip": target_ip,
            "domain": domain,
            "credential": {
                "username": cred_user,
                "password": cred_pass,
                "domain": cred_domain,
            },
            "instructions": concat!(
                "Run the certipy_find tool with vulnerable=true to enumerate vulnerable ",
                "certificate templates and CAs.\n\n",
                "IMPORTANT: You MUST pass vulnerable=true to certipy_find. Without it, the ",
                "output will not flag ESC vulnerabilities and no vulns will be registered.\n\n",
                "AUTHENTICATION: If password is empty and an NTLM hash is provided, use the ",
                "certipy_find tool with the 'hashes' parameter (format ':nthash'). Do NOT pass ",
                "an empty password.\n\n",
                "If a password IS provided, use certipy_find with 'password' parameter.\n\n",
                "For each vulnerable template found, register a vulnerability with:\n",
                "  vuln_type: the ESC type (e.g. 'esc1', 'esc2', 'esc3', 'esc4', 'esc6', 'esc8', 'esc10', 'esc11', 'esc15')\n",
                "  target: the certificate template name\n",
                "  target_ip: the CA server IP\n",
                "  domain: the domain\n",
                "  details: include template_name, ca_name, enrollee_supplies_subject, ",
                "client_authentication, any_purpose, enrollment_rights, and which users/groups can enroll\n\n",
                "Check for: ESC1 (Enrollee Supplies Subject + Client Auth), ESC2 (Any Purpose EKU), ",
                "ESC3 (enrollment agent), ESC4 (template ACL abuse), ESC6 (EDITF flag), ",
                "ESC7 (ManageCA), ESC8 (Web Enrollment HTTP relay), ESC9 (UPN Spoofing), ",
                "ESC10 (Weak Certificate Mapping / StrongCertificateBindingEnforcement=0), ",
                "ESC11 (RPC enrollment relay / IF_ENFORCEENCRYPTICERTREQUEST disabled), ",
                "ESC13 (Issuance Policy), ESC15 (Application Policy OID / CVE-2024-49019).\n",
                "If certipy_find fails, try with -stdout flag."
            ),
        });
        // Attach hash for PTH authentication
        if let Some(hash) = ntlm_hash {
            payload["ntlm_hash"] = json!(hash);
            if let Some(user) = hash_username {
                payload["hash_username"] = json!(user);
            }
        }
        // CA host IP for parser to set correct vuln target
        if let Some(ca_ip) = ca_host_ip {
            payload["ca_host_ip"] = json!(ca_ip);
        }
        // task_type "recon" → recon prompt template (supports instructions/ntlm_hash)
        // target_role "privesc" → privesc tools (certipy_find is only in privesc)
        self.throttled_submit("recon", "privesc", payload, 4).await
    }

    /// Refresh the operation lock TTL. Called periodically.
    pub async fn extend_lock(&self) -> Result<()> {
        let op_id = self.state.operation_id().await;
        self.queue.extend_lock(&op_id, self.config.lock_ttl).await?;
        Ok(())
    }

    /// Publish a state update notification via Redis PubSub.
    pub async fn notify_state_update(&self) -> Result<()> {
        let op_id = self.state.operation_id().await;
        self.queue.publish_state_update(&op_id).await?;
        Ok(())
    }
}
