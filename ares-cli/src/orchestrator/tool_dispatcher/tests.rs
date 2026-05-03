use super::*;

#[test]
fn tool_exec_request_serialization() {
    let req = ToolExecRequest {
        call_id: "nmap_scan_abc123".into(),
        task_id: "recon_def456".into(),
        tool_name: "nmap_scan".into(),
        arguments: serde_json::json!({"target": "192.168.58.0/24"}),
        traceparent: None,
        operation_id: Some("op-20260415-120000".into()),
    };

    let json = serde_json::to_string(&req).unwrap();
    let parsed: ToolExecRequest = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.call_id, "nmap_scan_abc123");
    assert_eq!(parsed.tool_name, "nmap_scan");
}

#[test]
fn tool_exec_response_deserialization() {
    let json = r#"{"call_id":"nmap_scan_abc","output":"Found 5 hosts","error":null}"#;
    let resp: ToolExecResponse = serde_json::from_str(json).unwrap();
    assert_eq!(resp.output, "Found 5 hosts");
    assert!(resp.error.is_none());
}

#[test]
fn tool_exec_response_with_error() {
    let json = r#"{"call_id":"x","output":"","error":"Connection refused"}"#;
    let resp: ToolExecResponse = serde_json::from_str(json).unwrap();
    assert_eq!(resp.error.as_deref(), Some("Connection refused"));
}

#[test]
fn cross_role_routing_netexec_tools() {
    // Netexec tools called from credential_access should route to recon
    assert_eq!(
        resolve_queue_role("credential_access", "password_spray"),
        "recon"
    );
    assert_eq!(
        resolve_queue_role("credential_access", "username_as_password"),
        "recon"
    );
    assert_eq!(
        resolve_queue_role("credential_access", "ldap_search_descriptions"),
        "recon"
    );
    assert_eq!(
        resolve_queue_role("credential_access", "gpp_password_finder"),
        "recon"
    );
    assert_eq!(
        resolve_queue_role("credential_access", "sysvol_script_search"),
        "recon"
    );
    assert_eq!(
        resolve_queue_role("credential_access", "laps_dump"),
        "recon"
    );
    assert_eq!(
        resolve_queue_role("credential_access", "smbclient_spider"),
        "recon"
    );
    assert_eq!(
        resolve_queue_role("credential_access", "password_policy"),
        "recon"
    );
}

#[test]
fn cross_role_routing_native_tools_stay() {
    // Tools native to credential_access should stay on credential_access
    assert_eq!(
        resolve_queue_role("credential_access", "secretsdump"),
        "credential_access"
    );
    assert_eq!(
        resolve_queue_role("credential_access", "kerberoast"),
        "credential_access"
    );
    assert_eq!(
        resolve_queue_role("credential_access", "lsassy"),
        "credential_access"
    );
}

#[test]
fn cross_role_routing_recon_stays_recon() {
    // When recon itself calls these tools, they stay on recon
    assert_eq!(resolve_queue_role("recon", "password_spray"), "recon");
    assert_eq!(resolve_queue_role("recon", "nmap_scan"), "recon");
    assert_eq!(
        resolve_queue_role("recon", "ldap_search_descriptions"),
        "recon"
    );
}

#[tokio::test]
async fn inject_excluded_users_no_state_is_noop() {
    let mut args = serde_json::json!({"target": "1.2.3.4", "domain": "contoso.local"});
    inject_excluded_users(&None, "password_spray", &mut args).await;
    assert!(args.get("excluded_users").is_none());
}

#[tokio::test]
async fn inject_excluded_users_skips_non_spray_tools() {
    let state = SharedState::new("op-1".into());
    state
        .write()
        .await
        .quarantine_user("testuser1", "contoso.local");
    let mut args = serde_json::json!({"target": "1.2.3.4", "domain": "contoso.local"});
    inject_excluded_users(&Some(state), "smb_login_check", &mut args).await;
    assert!(args.get("excluded_users").is_none());
}

#[tokio::test]
async fn inject_excluded_users_populates_from_state() {
    let state = SharedState::new("op-1".into());
    {
        let mut s = state.write().await;
        s.quarantine_user("testuser1", "contoso.local");
        s.quarantine_user("testuser2", "contoso.local");
        s.quarantine_user("testuser3", "fabrikam.local");
    }
    let mut args = serde_json::json!({"target": "1.2.3.4", "domain": "contoso.local"});
    inject_excluded_users(&Some(state), "password_spray", &mut args).await;
    let excluded = args
        .get("excluded_users")
        .and_then(|v| v.as_str())
        .unwrap();
    let mut parts: Vec<&str> = excluded.split(',').collect();
    parts.sort();
    assert_eq!(parts, vec!["testuser1", "testuser2"]);
}

#[tokio::test]
async fn inject_excluded_users_unions_with_existing() {
    let state = SharedState::new("op-1".into());
    state
        .write()
        .await
        .quarantine_user("testuser1", "contoso.local");
    let mut args = serde_json::json!({
        "target": "1.2.3.4",
        "domain": "contoso.local",
        "excluded_users": "Administrator,testuser2",
    });
    inject_excluded_users(&Some(state), "username_as_password", &mut args).await;
    let excluded = args
        .get("excluded_users")
        .and_then(|v| v.as_str())
        .unwrap();
    let mut parts: Vec<&str> = excluded.split(',').collect();
    parts.sort();
    assert_eq!(parts, vec!["administrator", "testuser1", "testuser2"]);
}

#[tokio::test]
async fn inject_excluded_users_no_domain_is_noop() {
    let state = SharedState::new("op-1".into());
    state
        .write()
        .await
        .quarantine_user("testuser1", "contoso.local");
    let mut args = serde_json::json!({"target": "1.2.3.4"});
    inject_excluded_users(&Some(state), "password_spray", &mut args).await;
    assert!(args.get("excluded_users").is_none());
}
