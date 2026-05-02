//! In-process tool dispatcher (no Redis).

use anyhow::Result;
use tracing::{debug, warn};

use ares_llm::{ToolCall, ToolExecResult};

use crate::orchestrator::task_queue::TaskQueue;
use crate::worker::credential_resolver::resolve_credentials;

use super::domain_validator::check_domain_arg;
use super::{extract_credential_key, push_realtime_discoveries, AuthThrottle};

/// Dispatches tool calls directly via `ares_tools::dispatch` without Redis.
///
/// Useful for testing, single-binary deployments, or when workers are
/// colocated in the same process as the orchestrator.
pub struct LocalToolDispatcher {
    pub(super) queue: TaskQueue,
    pub(super) operation_id: String,
    pub(super) auth_throttle: AuthThrottle,
}

impl LocalToolDispatcher {
    pub fn new(queue: TaskQueue, operation_id: String, auth_throttle: AuthThrottle) -> Self {
        Self {
            queue,
            operation_id,
            auth_throttle,
        }
    }
}

#[async_trait::async_trait]
impl ares_llm::ToolDispatcher for LocalToolDispatcher {
    async fn dispatch_tool(
        &self,
        _role: &str,
        _task_id: &str,
        call: &ToolCall,
    ) -> Result<ToolExecResult> {
        // Reject calls whose `domain` argument doesn't match a known domain.
        if let Some(rejection) = check_domain_arg(&self.queue, &self.operation_id, call).await {
            return Ok(rejection);
        }

        // Rate-limit auth-bearing tools to prevent AD account lockout
        if let Some(cred_key) = extract_credential_key(call) {
            self.auth_throttle.acquire(&cred_key).await;
        }

        debug!(tool = %call.name, "Executing tool locally");

        // Resolve credentials from operation state. The LLM never passes
        // secret material — usernames + domains only. Mirrors the worker
        // tool_executor path so local (in-process) dispatch gets the same
        // injection.
        let mut resolved_arguments = call.arguments.clone();
        let mut conn = self.queue.connection();
        if let Err(e) = resolve_credentials(
            &mut conn,
            Some(self.operation_id.as_str()),
            &call.name,
            &mut resolved_arguments,
        )
        .await
        {
            warn!(
                tool = %call.name,
                err = %e,
                "credential_resolver failed; continuing with original arguments"
            );
            resolved_arguments = call.arguments.clone();
        }

        match ares_tools::dispatch(&call.name, &resolved_arguments).await {
            Ok(output) => {
                let raw = output.combined_raw();
                let combined = output.combined();
                let error = if output.success {
                    None
                } else {
                    Some(format!("tool exited with code {:?}", output.exit_code))
                };

                // Parse structured discoveries from raw (unfiltered) output
                let discoveries =
                    ares_tools::parsers::parse_tool_output(&call.name, &raw, &resolved_arguments);
                let discoveries = if discoveries.as_object().is_none_or(|o| o.is_empty()) {
                    None
                } else {
                    Some(discoveries)
                };

                // Push discoveries to real-time list immediately (like RedisToolDispatcher)
                if let Some(ref disc) = discoveries {
                    push_realtime_discoveries(
                        &self.queue,
                        &self.operation_id,
                        disc,
                        &call.name,
                        &resolved_arguments,
                    )
                    .await;
                }

                Ok(ToolExecResult {
                    output: combined,
                    error,
                    discoveries,
                })
            }
            Err(e) => Ok(ToolExecResult {
                output: String::new(),
                error: Some(e.to_string()),
                discoveries: None,
            }),
        }
    }
}
