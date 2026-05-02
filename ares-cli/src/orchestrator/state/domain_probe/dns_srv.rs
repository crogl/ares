//! DNS SRV-based domain prober.
//!
//! Real AD domains publish `_ldap._tcp.dc._msdcs.<domain>` SRV records. This
//! is the same lookup that NetExec, runZero, and BloodHound use to discover
//! domain controllers, and it serves equally well as a binary "is this a real
//! AD domain?" probe.
//!
//! Resolver behavior:
//! - We construct a `TokioAsyncResolver` from the system resolv.conf so we
//!   pick up whatever recursive resolver the operator has configured (often
//!   the same DNS server an attacker would query during real-world recon).
//! - NXDOMAIN / NoRecordsFound → `Rejected` (the suffix is definitely not AD).
//! - Successful answer with at least one SRV record → `Confirmed`.
//! - I/O / timeout / refused → `Indeterminate` (we'll retry next tick).

use async_trait::async_trait;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::error::ResolveErrorKind;
use hickory_resolver::TokioAsyncResolver;

use super::{DomainProber, ProbeOutcome};

/// Real DNS prober. Wraps a hickory `TokioAsyncResolver`.
pub struct DnsSrvProber {
    resolver: TokioAsyncResolver,
}

impl DnsSrvProber {
    /// Construct using the system resolver (resolv.conf on Unix).
    /// Falls back to a Cloudflare/Google config if system config is unreadable
    /// — we still need *something* to query in container environments where
    /// /etc/resolv.conf may be missing.
    pub fn from_system() -> Self {
        let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(err = %e, "DNS SRV prober: system resolver unreadable, falling back to defaults");
                TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
            }
        };
        Self { resolver }
    }
}

#[async_trait]
impl DomainProber for DnsSrvProber {
    async fn probe(&self, fqdn: &str) -> ProbeOutcome {
        let query = format!("_ldap._tcp.dc._msdcs.{}.", fqdn.trim_end_matches('.'));
        match self.resolver.srv_lookup(&query).await {
            Ok(answer) => {
                if answer.iter().next().is_some() {
                    ProbeOutcome::Confirmed
                } else {
                    ProbeOutcome::Rejected("no SRV records")
                }
            }
            Err(e) => match e.kind() {
                ResolveErrorKind::NoRecordsFound { .. } => {
                    ProbeOutcome::Rejected("NXDOMAIN / no _ldap._tcp.dc._msdcs SRV")
                }
                _ => {
                    tracing::debug!(fqdn = %fqdn, err = %e, "DNS SRV probe transient error");
                    ProbeOutcome::Indeterminate
                }
            },
        }
    }
}
