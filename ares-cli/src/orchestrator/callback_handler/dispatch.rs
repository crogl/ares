//! Dispatch tools — submit sub-tasks via the Dispatcher, and disabled record tools.

use anyhow::Result;
use tracing::{info, warn};

use ares_llm::provider::ToolCall;
use ares_llm::CallbackResult;

use super::OrchestratorCallbackHandler;

impl OrchestratorCallbackHandler {
    pub(super) async fn dispatch_recon(&self, call: &ToolCall) -> Result<CallbackResult> {
        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let target_ip = call.arguments["target_ip"].as_str().unwrap_or("");
        let domain = call.arguments["domain"].as_str().unwrap_or("");
        let techniques: Vec<&str> = call.arguments["techniques"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();

        let task_id = dispatcher
            .request_recon(target_ip, domain, &techniques, None)
            .await?;

        info!(target_ip = target_ip, "Dispatched recon task");
        Ok(CallbackResult::Continue(format!(
            "Recon task dispatched: {}",
            task_id.as_deref().unwrap_or("queued")
        )))
    }

    pub(super) async fn dispatch_credential_access(
        &self,
        call: &ToolCall,
    ) -> Result<CallbackResult> {
        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let technique = call.arguments["technique"]
            .as_str()
            .unwrap_or("secretsdump");
        let target_ip = call.arguments["target_ip"].as_str().unwrap_or("");
        let domain = call.arguments["domain"].as_str().unwrap_or("");
        let username = call.arguments["username"].as_str().unwrap_or("");
        let password = call.arguments["password"].as_str().unwrap_or("");
        let priority = call.arguments["priority"].as_i64().unwrap_or(5) as i32;

        let cred = ares_core::models::Credential {
            id: uuid::Uuid::new_v4().to_string(),
            username: username.to_string(),
            password: password.to_string(),
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };

        let task_id = dispatcher
            .request_credential_access(technique, target_ip, domain, &cred, priority)
            .await?;

        info!(
            technique = technique,
            target_ip = target_ip,
            "Dispatched credential access task"
        );
        Ok(CallbackResult::Continue(format!(
            "Credential access task ({technique}) dispatched: {}",
            task_id.as_deref().unwrap_or("queued")
        )))
    }

    pub(super) async fn dispatch_lateral(&self, call: &ToolCall) -> Result<CallbackResult> {
        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let target_ip = call.arguments["target_ip"].as_str().unwrap_or("");
        let technique = call.arguments["technique"].as_str().unwrap_or("psexec");
        let username = call.arguments["username"].as_str().unwrap_or("");
        let password = call.arguments["password"].as_str().unwrap_or("");
        let domain = call.arguments["domain"].as_str().unwrap_or("");

        let cred = ares_core::models::Credential {
            id: uuid::Uuid::new_v4().to_string(),
            username: username.to_string(),
            password: password.to_string(),
            domain: domain.to_string(),
            source: String::new(),
            discovered_at: None,
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };

        // Pre-check cross-realm so the LLM gets a clear "dead-end" message
        // rather than a misleading "queued" when request_lateral silently rejects.
        let target_realm = {
            let state = self.state.read().await;
            state
                .hosts
                .iter()
                .find(|h| h.ip == target_ip)
                .and_then(|h| h.hostname.split_once('.').map(|(_, d)| d.to_lowercase()))
        };
        if let Some(td) = target_realm {
            let cd = domain.to_lowercase();
            if !cd.is_empty()
                && cd != td
                && !td.ends_with(&format!(".{cd}"))
                && !cd.ends_with(&format!(".{td}"))
            {
                warn!(
                    target_ip = target_ip,
                    target_realm = %td,
                    cred_domain = %cd,
                    cred_user = username,
                    technique = technique,
                    "Rejecting cross-realm lateral from LLM — returning dead-end message"
                );
                return Ok(CallbackResult::Continue(format!(
                    "REJECTED: cross-realm lateral movement ({cd} cred → {td} target at {target_ip}) \
                     will not work. Windows strips ExtraSid RID<1000 across forests, and same-realm \
                     auth is required for SMB/WMI/PSExec. DO NOT retry this combination with any \
                     {technique}/pth_*/smbexec/wmiexec/psexec variant. Instead: dispatch \
                     forest_trust_escalation, exploit ESC8/MSSQL/ACL paths to acquire a \
                     {td}-realm credential, or pivot via FSP membership."
                )));
            }
        }

        let task_id = dispatcher
            .request_lateral(target_ip, &cred, technique)
            .await?;

        info!(
            technique = technique,
            target_ip = target_ip,
            "Dispatched lateral movement task"
        );
        Ok(CallbackResult::Continue(format!(
            "Lateral movement ({technique}) dispatched to {target_ip}: {}",
            task_id.as_deref().unwrap_or("queued")
        )))
    }

    pub(super) async fn dispatch_exploit(&self, call: &ToolCall) -> Result<CallbackResult> {
        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let vuln_id = call.arguments["vuln_id"].as_str().unwrap_or("");
        let priority = call.arguments["priority"].as_i64().unwrap_or(3) as i32;

        // Look up vulnerability in state
        let state = self.state.read().await;
        let vuln = state.discovered_vulnerabilities.get(vuln_id);

        if let Some(vuln) = vuln {
            let vuln = vuln.clone();
            drop(state); // Release lock before async dispatch

            let task_id = dispatcher.request_exploit(&vuln, priority).await?;
            info!(vuln_id = vuln_id, "Dispatched exploit task");
            Ok(CallbackResult::Continue(format!(
                "Exploit task for {} dispatched: {}",
                vuln_id,
                task_id.as_deref().unwrap_or("queued")
            )))
        } else {
            drop(state);
            Ok(CallbackResult::Continue(format!(
                "Vulnerability {vuln_id} not found in discovered vulnerabilities"
            )))
        }
    }

    pub(super) async fn dispatch_coercion(&self, call: &ToolCall) -> Result<CallbackResult> {
        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let target_ip = call.arguments["target_ip"].as_str().unwrap_or("");
        let listener_ip = call.arguments["listener_ip"].as_str().unwrap_or("");
        let techniques: Vec<&str> = call.arguments["techniques"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_else(|| vec!["petitpotam", "printerbug"]);

        let task_id = dispatcher
            .request_coercion(target_ip, listener_ip, &techniques)
            .await?;

        info!(target_ip = target_ip, "Dispatched coercion task");
        Ok(CallbackResult::Continue(format!(
            "Coercion task dispatched to {target_ip}: {}",
            task_id.as_deref().unwrap_or("queued")
        )))
    }

    /// record_credential is disabled — credentials come only from tool output parsing.
    /// This handler exists as a safety net in case the LLM somehow invokes it.
    pub(super) async fn record_credential(&self, _call: &ToolCall) -> Result<CallbackResult> {
        warn!("record_credential called but disabled — credentials are auto-extracted from tool output");
        Ok(CallbackResult::Continue(
            "This tool is disabled. Credentials are automatically extracted from tool output. \
             Focus on running tools that produce credential data (secretsdump, lsassy, netexec, etc.) \
             and the system will parse and store credentials automatically."
                .to_string(),
        ))
    }

    /// record_timeline_event is disabled — timeline events are auto-generated from
    /// state changes (credential/hash/host discoveries) in result_processing.rs.
    /// This handler exists as a safety net in case the LLM somehow invokes it.
    pub(super) async fn record_timeline_event(&self, _call: &ToolCall) -> Result<CallbackResult> {
        warn!("record_timeline_event called but disabled — timeline events are auto-generated from discoveries");
        Ok(CallbackResult::Continue(
            "This tool is disabled. Timeline events are automatically generated when \
             credentials, hashes, and hosts are discovered from tool output. Focus on \
             running attack tools and the system will build the timeline automatically."
                .to_string(),
        ))
    }

    pub(super) async fn dispatch_crack(&self, call: &ToolCall) -> Result<CallbackResult> {
        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let hash_value = call.arguments["hash_value"].as_str().unwrap_or("");
        let hash_type = call.arguments["hash_type"].as_str().unwrap_or("ntlm");
        let username = call.arguments["username"].as_str().unwrap_or("");
        let domain = call.arguments["domain"].as_str().unwrap_or("");

        let hash = ares_core::models::Hash {
            id: uuid::Uuid::new_v4().to_string(),
            username: username.to_string(),
            hash_value: hash_value.to_string(),
            hash_type: hash_type.to_string(),
            domain: domain.to_string(),
            cracked_password: None,
            source: String::new(),
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
            aes_key: None,
            is_previous: false,
            source_host: None,
            is_trust_key: false,
            trust_pair_label: None,
        };

        let task_id = dispatcher.request_crack(&hash).await?;

        info!(hash_type = hash_type, "Dispatched crack task");
        Ok(CallbackResult::Continue(format!(
            "Crack task dispatched for {username}@{domain} ({hash_type}): {}",
            task_id.as_deref().unwrap_or("queued")
        )))
    }

    /// Structured fallback for the cracker LLM agent. The preferred path is
    /// still raw stdout extraction by `output_extraction.rs`, but when the LLM
    /// summarizes its result instead of piping the raw `--show` line through
    /// `tool_outputs`, the cleartext is lost. This callback gives the LLM an
    /// unambiguous channel to land the credential. Every value passes through
    /// `is_valid_credential`, which rejects hash-shaped strings and LLM
    /// truncation artifacts — so a confused LLM can't pollute state with
    /// fabricated passwords.
    pub(super) async fn report_cracked_credential(
        &self,
        call: &ToolCall,
    ) -> Result<CallbackResult> {
        let username = call.arguments["username"]
            .as_str()
            .unwrap_or("")
            .trim()
            .to_string();
        let domain = call.arguments["domain"]
            .as_str()
            .unwrap_or("")
            .trim()
            .to_lowercase();
        let password = call.arguments["password"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let hash_type = call.arguments["hash_type"]
            .as_str()
            .unwrap_or("")
            .to_string();

        // Validate inputs BEFORE touching the dispatcher so rejection paths
        // don't trip on a missing dispatcher in tests / partial init.
        if username.is_empty() || domain.is_empty() || password.is_empty() {
            return Ok(CallbackResult::Continue(
                "report_cracked_credential requires non-empty username, domain, and password."
                    .to_string(),
            ));
        }

        // Reuse the same boundary validator that gates auto-extraction. This
        // rejects NTLM-shaped 32-hex strings, $krb5*$ blobs, ellipsis-truncated
        // hash displays, and the other shapes documented in
        // `output_extraction/mod.rs::is_valid_credential`.
        if !crate::orchestrator::output_extraction::is_valid_credential(&username, &password) {
            warn!(
                username = %username,
                domain = %domain,
                "report_cracked_credential rejected by validator (looks like a hash or truncated display, not a real password)"
            );
            return Ok(CallbackResult::Continue(
                "Rejected. The password you reported looks like a hash, a truncated display, \
                 or otherwise not a real cleartext password. Re-run the cracker and emit the \
                 actual `--show` plaintext, or run `crack_with_hashcat` again with a different \
                 wordlist. Do not paraphrase or truncate cracked passwords."
                    .to_string(),
            ));
        }

        let dispatcher = self
            .dispatcher
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Dispatcher not configured"))?;

        let credential = ares_core::models::Credential {
            id: uuid::Uuid::new_v4().to_string(),
            username: username.clone(),
            password: password.clone(),
            domain: domain.clone(),
            source: format!(
                "cracked:report_callback{}",
                if hash_type.is_empty() {
                    String::new()
                } else {
                    format!(":{hash_type}")
                }
            ),
            discovered_at: Some(chrono::Utc::now()),
            is_admin: false,
            parent_id: None,
            attack_step: 0,
        };

        match dispatcher
            .state
            .publish_credential(&dispatcher.queue, credential)
            .await
        {
            Ok(true) => {
                // Mirror the post-publish hash-annotation that the auto-
                // extraction path runs, so the matching hash record reflects
                // the cleartext regardless of which path produced it.
                let _ = dispatcher
                    .state
                    .update_hash_cracked_password(&dispatcher.queue, &username, &domain, &password)
                    .await;
                info!(
                    username = %username,
                    domain = %domain,
                    hash_type = %hash_type,
                    "Cracked credential published via report_cracked_credential"
                );
                Ok(CallbackResult::Continue(format!(
                    "Cracked credential stored: {username}@{domain}. Annotated matching hash with the cleartext."
                )))
            }
            Ok(false) => Ok(CallbackResult::Continue(format!(
                "Credential {username}@{domain} already known — no-op."
            ))),
            Err(e) => {
                warn!(err = %e, "Failed to publish cracked credential");
                Ok(CallbackResult::Continue(format!(
                    "Failed to publish credential: {e}"
                )))
            }
        }
    }
}
