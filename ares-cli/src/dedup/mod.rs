pub(crate) mod credentials;
pub(crate) mod domains;
pub(crate) mod hashes;
pub(crate) mod labels;
pub(crate) mod users;

#[cfg(test)]
mod tests;

use regex::Regex;
use std::sync::LazyLock;

/// Strip trailing DNS root dot and NetExec "0." artifact from domain strings
/// (e.g. `child.contoso.local.` → `child.contoso.local`,
/// `contoso.local0` → `contoso.local`).
pub(super) fn strip_trailing_dot(s: &str) -> &str {
    let s = s.trim_end_matches('.');
    // NetExec sometimes appends "0" to domain TLDs. Strip if the char
    // before the trailing 0 is alphabetic (i.e. TLD-like, not "host10").
    match s.strip_suffix('0') {
        Some(clean) if clean.ends_with(|c: char| c.is_ascii_alphabetic()) => clean,
        _ => s,
    }
}

/// Auto-generated Windows hostname pattern (`WIN-` + 11 alphanumerics + optional `$`).
/// Used to filter ghost machine accounts that the agent created itself via
/// NoPAC / MachineAccountQuota — not real lab hosts, just our own residue.
static GHOST_MACHINE_ACCOUNT_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^WIN-[A-Z0-9]{11}\$?$").unwrap());

/// True if `username` looks like an auto-generated Windows machine account
/// (e.g. `WIN-G9FWV8ZNSCL$`) — typically agent-created via NoPAC.
pub(crate) fn is_ghost_machine_account(username: &str) -> bool {
    GHOST_MACHINE_ACCOUNT_RE.is_match(username.trim())
}

pub(crate) use credentials::{dedup_credentials, sanitize_credentials};
pub(crate) use domains::normalize_state_domains;
pub(crate) use hashes::dedup_hashes;
pub(crate) use labels::normalize_source_label;
pub(crate) use users::dedup_users;
