use std::sync::Arc;

use tokio::sync::watch;
use tracing::info;

use crate::orchestrator::automation;
use crate::orchestrator::dispatcher::Dispatcher;

/// Spawn all automation background tasks. Returns their JoinHandles.
pub(crate) fn spawn_automation_tasks(
    dispatcher: Arc<Dispatcher>,
    shutdown_rx: watch::Receiver<bool>,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = Vec::new();

    macro_rules! spawn_auto {
        ($name:ident) => {{
            let d = dispatcher.clone();
            let s = shutdown_rx.clone();
            handles.push(tokio::spawn(async move {
                automation::$name(d, s).await;
            }));
        }};
    }

    spawn_auto!(auto_crack_dispatch);
    spawn_auto!(auto_mssql_detection);
    spawn_auto!(auto_adcs_enumeration);
    spawn_auto!(auto_adcs_exploitation);
    spawn_auto!(auto_share_enumeration);
    spawn_auto!(auto_share_spider);
    spawn_auto!(auto_bloodhound);
    spawn_auto!(auto_delegation_enumeration);
    spawn_auto!(auto_coercion);
    spawn_auto!(auto_local_admin_secretsdump);
    spawn_auto!(auto_credential_access);
    spawn_auto!(auto_credential_expansion);
    spawn_auto!(auto_golden_ticket);
    spawn_auto!(auto_acl_chain_follow);
    spawn_auto!(auto_trust_follow);
    spawn_auto!(auto_s4u_exploitation);
    spawn_auto!(auto_gmsa_extraction);
    spawn_auto!(auto_unconstrained_exploitation);
    spawn_auto!(auto_stall_detection);
    spawn_auto!(auto_credential_reuse);
    spawn_auto!(auto_shadow_credentials);
    spawn_auto!(auto_rbcd_exploitation);
    spawn_auto!(auto_mssql_exploitation);
    spawn_auto!(auto_gpo_abuse);
    spawn_auto!(auto_laps_extraction);
    spawn_auto!(auto_ntlm_relay);
    spawn_auto!(auto_nopac);
    spawn_auto!(auto_zerologon);
    spawn_auto!(auto_print_nightmare);
    spawn_auto!(auto_smb_signing_detection);
    spawn_auto!(auto_share_coercion);
    spawn_auto!(auto_mssql_coercion);
    spawn_auto!(auto_password_policy);
    spawn_auto!(auto_gpp_sysvol);
    spawn_auto!(auto_ntlmv1_downgrade);
    spawn_auto!(auto_ldap_signing);
    spawn_auto!(auto_webdav_detection);
    spawn_auto!(auto_spooler_check);
    spawn_auto!(auto_machine_account_quota);
    spawn_auto!(auto_dfs_coercion);
    spawn_auto!(auto_petitpotam_unauth);
    spawn_auto!(auto_winrm_lateral);
    spawn_auto!(auto_group_enumeration);
    spawn_auto!(auto_localuser_spray);
    spawn_auto!(auto_krbrelayup);
    spawn_auto!(auto_searchconnector_coercion);
    spawn_auto!(auto_lsassy_dump);
    spawn_auto!(auto_rdp_lateral);
    spawn_auto!(auto_foreign_group_enum);
    spawn_auto!(auto_certipy_auth);
    spawn_auto!(auto_sid_enumeration);
    spawn_auto!(auto_dns_enum);
    spawn_auto!(auto_domain_user_enum);
    spawn_auto!(auto_pth_spray);
    spawn_auto!(auto_certifried);

    info!(count = handles.len(), "Automation tasks spawned");
    handles
}
