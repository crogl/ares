//! Recon task prompt generation.

use serde_json::Value;
use tera::Context;

use super::helpers::{insert_credential_context, insert_state_context};
use super::templates::{render_template_with_context, TASK_RECON};
use super::StateSnapshot;

pub(crate) fn generate_recon_prompt(
    task_id: &str,
    payload: &Value,
    state: Option<&StateSnapshot>,
) -> anyhow::Result<String> {
    let mut ctx = Context::new();
    ctx.insert("task_id", task_id);
    ctx.insert(
        "target_ip",
        payload["target_ip"].as_str().unwrap_or("unknown"),
    );

    let domain = payload["domain"].as_str().unwrap_or("");
    if !domain.is_empty() {
        ctx.insert("domain", domain);
    }

    insert_credential_context(&mut ctx, payload);

    let techniques: Vec<&str> = payload["techniques"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if !techniques.is_empty() {
        ctx.insert("techniques", &techniques);
    }

    // Single technique (e.g. certipy_find, ldap_group_enumeration)
    if let Some(technique) = payload["technique"].as_str() {
        ctx.insert("technique", technique);
    }

    // Task-specific instructions (e.g. certipy commands, LDAP queries)
    if let Some(instructions) = payload["instructions"].as_str() {
        ctx.insert("instructions", instructions);
    }

    // Surface the principal that owns a usable NTLM hash so the LLM can
    // reference it by name. The hash value itself is never inserted — the
    // worker injects the hash at dispatch from operation state.
    if let Some(hash_username) = payload["hash_username"].as_str() {
        if !hash_username.is_empty() {
            ctx.insert("hash_username", hash_username);
            ctx.insert("has_ntlm_hash", &true);
        }
    } else if payload["ntlm_hash"].as_str().is_some() {
        ctx.insert("has_ntlm_hash", &true);
    }

    insert_state_context(&mut ctx, state, "recon", payload["target_ip"].as_str());

    render_template_with_context(TASK_RECON, &ctx)
}
