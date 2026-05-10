//! auto_crack_dispatch -- submit crack tasks for new hashes.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

use super::crack_dedup_key;

/// Cracking-priority bucket for a hash type. Lower is higher priority.
///
/// Kerberoast and AS-REP hashes are the high-leverage crack targets in any
/// op: a cracked SPN often exposes a service account the orchestrator
/// already knows how to abuse (linked-server pivots, MSSQL impersonation,
/// cross-forest reuse), and AS-REP plaintext lets us swap an LLM-blind
/// password into the credential pool. NTLM hashes from secretsdump are
/// already usable as-is via PtH, so cracking them is the lowest-payoff
/// work and should never block roastable hashes from the single hashcat
/// slot.
fn crack_priority(hash_type: &str) -> u8 {
    match hash_type.to_ascii_lowercase().as_str() {
        "kerberoast" | "asrep" | "asreproast" => 0,
        _ => 1,
    }
}

/// Scans for uncracked hashes and submits crack tasks.
/// Interval: 15s. Matches Python `_auto_crack_dispatch`.
pub async fn auto_crack_dispatch(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        // Collect unprocessed hashes, then sort by crack priority so the
        // single hashcat slot serves roastable hashes first. Without this,
        // a backlog of NTLM machine-account hashes from secretsdump (already
        // PtH-usable) starves the lone kerberoast/asrep hash that would
        // unlock a service-account password — exactly the failure mode that
        // left a kerberoasted sql_svc untouched for hours in op-20260510.
        let mut work: Vec<(String, ares_core::models::Hash)> = {
            let state = dispatcher.state.read().await;
            state
                .hashes
                .iter()
                .filter(|h| h.cracked_password.is_none())
                .filter_map(|h| {
                    let dedup = crack_dedup_key(h);
                    if state.is_processed(DEDUP_CRACK_REQUESTS, &dedup) {
                        None
                    } else {
                        Some((dedup, h.clone()))
                    }
                })
                .collect()
        };
        work.sort_by_key(|(_, h)| crack_priority(&h.hash_type));

        // Serialize crack tasks: hashcat only allows one instance at a time.
        // Skip this tick if a cracker task is already running.
        if dispatcher.tracker.count_for_role("cracker").await > 0 {
            debug!("Crack task already active, skipping dispatch this tick");
            continue;
        }

        // Only dispatch one crack task per tick to avoid hashcat PID conflicts.
        // Remaining hashes will be picked up on subsequent ticks.
        if let Some((dedup_key, hash)) = work.into_iter().next() {
            match dispatcher.request_crack(&hash).await {
                Ok(Some(task_id)) => {
                    debug!(task_id = %task_id, hash_type = %hash.hash_type, "Crack task dispatched");
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_CRACK_REQUESTS, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_CRACK_REQUESTS, &dedup_key)
                        .await;
                }
                Ok(None) => {} // deferred or throttled
                Err(e) => warn!(err = %e, "Failed to dispatch crack task"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::crack_priority;

    #[test]
    fn roastable_hashes_outrank_ntlm() {
        assert!(crack_priority("kerberoast") < crack_priority("ntlm"));
        assert!(crack_priority("asrep") < crack_priority("ntlm"));
        assert!(crack_priority("asreproast") < crack_priority("ntlm"));
    }

    #[test]
    fn roastable_priority_case_insensitive() {
        assert_eq!(crack_priority("KERBEROAST"), crack_priority("kerberoast"));
        assert_eq!(crack_priority("AsRep"), crack_priority("asrep"));
    }

    #[test]
    fn unknown_hash_types_share_ntlm_bucket() {
        assert_eq!(crack_priority("ntlm"), crack_priority("netntlmv2"));
        assert_eq!(crack_priority("ntlm"), crack_priority(""));
    }

    #[test]
    fn sort_places_roastable_first() {
        let mut v = ["ntlm", "kerberoast", "ntlm", "asrep"];
        v.sort_by_key(|t| crack_priority(t));
        // First two slots are the roastable ones in some order; last two are ntlm.
        assert!(matches!(v[0], "kerberoast" | "asrep"));
        assert!(matches!(v[1], "kerberoast" | "asrep"));
        assert_eq!(v[2], "ntlm");
        assert_eq!(v[3], "ntlm");
    }
}
