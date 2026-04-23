use regex::Regex;
use std::sync::LazyLock;

use ares_core::models::User;

static RE_DOMAIN_CONTEXT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\(domain:([^)]+)\)").unwrap());

pub(crate) static RE_DOMAIN_BACKSLASH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([A-Za-z0-9_.\-]+)\\([A-Za-z0-9_.\-$]+)").unwrap());

pub(crate) static RE_UPN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"([A-Za-z0-9_.\-]+)@([A-Za-z0-9_.\-]+\.[A-Za-z0-9_.\-]+)").unwrap()
});

pub(crate) static RE_USER_BRACKET: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)user:\[([^\]]+)\]").unwrap());

pub(crate) static RE_ACCOUNT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"Account:\s*([A-Za-z0-9_.\-]+)").unwrap());

static RE_SAM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)samaccountname:\s*([A-Za-z0-9_.\-]+)").unwrap());

static RE_SMB_TIMESTAMP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"SMB\s+\S+\s+\d+\s+\S+\s+([A-Za-z0-9_.\-]+)\s+\d{4}-\d{2}-\d{2}").unwrap()
});

/// Check if a domain string looks like a machine hostname rather than an AD domain.
///
/// Machine FQDNs like `win-g7fpa5zzxzv.w5an.local` or NetBIOS machine names like
/// `WIN-G7FPA5ZZXZV` pollute domain tracking when they appear in SMB banners or
/// UPN suffixes (e.g., null session enum on a DC reports the Kali box's own domain).
pub fn is_machine_hostname_domain(domain: &str) -> bool {
    let first_label = domain.split('.').next().unwrap_or(domain);
    let lower = first_label.to_lowercase();
    // Windows auto-generated hostnames: WIN-XXXXXXXX, DESKTOP-XXXXXXX
    if lower.starts_with("win-") || lower.starts_with("desktop-") {
        return true;
    }
    false
}

/// Reject garbage usernames and invalid domains from regex extraction.
pub fn is_valid_extracted_user(username: &str, domain: &str) -> bool {
    if username.is_empty() || username.ends_with('$') {
        return false;
    }
    if username.bytes().any(|b| b < 0x20) || domain.bytes().any(|b| b < 0x20) {
        return false;
    }
    if username.len() <= 1 {
        return false;
    }
    let lower = username.to_lowercase();
    const NOISE: &[&str] = &[
        "anonymous",
        "none",
        "null",
        "unknown",
        "n/a",
        "default",
        "test",
        "local",
        "localhost",
        "domain",
        "workgroup",
    ];
    if NOISE.contains(&lower.as_str()) {
        return false;
    }
    if username.starts_with('_') || domain.starts_with('_') {
        return false;
    }
    if !domain.contains('.') {
        if domain.len() > 15 || domain.is_empty() {
            return false;
        }
        if !domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
    }
    if !username.bytes().all(|b| b.is_ascii_graphic()) {
        return false;
    }
    true
}

pub fn extract_users(output: &str, default_domain: &str) -> Vec<User> {
    let mut users = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut current_domain = default_domain.to_string();

    for line in output.lines() {
        let stripped = line.trim();

        if let Some(caps) = RE_DOMAIN_CONTEXT.captures(stripped) {
            let captured = caps
                .get(1)
                .unwrap()
                .as_str()
                .trim_end_matches('.')
                .to_string();
            // Don't let machine hostnames (e.g. from Kali's own SMB banner)
            // override the task's default domain.
            if !is_machine_hostname_domain(&captured) {
                current_domain = captured;
            }
        }

        let mut found = Vec::new();

        if let Some(caps) = RE_DOMAIN_BACKSLASH.captures(stripped) {
            let dom = caps.get(1).unwrap().as_str();
            let user = caps.get(2).unwrap().as_str();
            found.push((user.to_string(), dom.to_string()));
        }

        if let Some(caps) = RE_UPN.captures(stripped) {
            let user = caps.get(1).unwrap().as_str();
            let dom = caps.get(2).unwrap().as_str();
            // If UPN suffix is a machine hostname (e.g. user@win-xxx.w5an.local),
            // substitute the default domain to avoid storing garbage domains.
            if is_machine_hostname_domain(dom) {
                found.push((user.to_string(), default_domain.to_string()));
            } else {
                found.push((user.to_string(), dom.to_string()));
            }
        }

        for caps in RE_USER_BRACKET.captures_iter(stripped) {
            let user = caps.get(1).unwrap().as_str();
            found.push((user.to_string(), current_domain.clone()));
        }

        if let Some(caps) = RE_ACCOUNT.captures(stripped) {
            let user = caps.get(1).unwrap().as_str();
            found.push((user.to_string(), current_domain.clone()));
        }

        if let Some(caps) = RE_SAM.captures(stripped) {
            let user = caps.get(1).unwrap().as_str();
            found.push((user.to_string(), current_domain.clone()));
        }

        if let Some(caps) = RE_SMB_TIMESTAMP.captures(stripped) {
            let user = caps.get(1).unwrap().as_str();
            found.push((user.to_string(), current_domain.clone()));
        }

        for (raw_username, raw_domain) in found {
            let username = raw_username.trim().trim_end_matches('.').to_string();
            let domain = raw_domain.trim().trim_end_matches('.').to_string();
            if !is_valid_extracted_user(&username, &domain) {
                continue;
            }
            let key = format!("{}@{}", username.to_lowercase(), domain.to_lowercase());
            if seen.insert(key) {
                users.push(User {
                    username,
                    domain,
                    description: String::new(),
                    is_admin: false,
                    source: "output_extraction".to_string(),
                });
            }
        }
    }

    users
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_valid_extracted_user_accepts_normal() {
        assert!(is_valid_extracted_user("alice", "contoso.local"));
    }

    #[test]
    fn is_valid_extracted_user_rejects_machine_account() {
        assert!(!is_valid_extracted_user("DC01$", "contoso.local"));
    }

    #[test]
    fn is_valid_extracted_user_rejects_empty() {
        assert!(!is_valid_extracted_user("", "contoso.local"));
    }

    #[test]
    fn is_valid_extracted_user_rejects_single_char() {
        assert!(!is_valid_extracted_user("a", "contoso.local"));
    }

    #[test]
    fn is_valid_extracted_user_rejects_noise_names() {
        for name in &["anonymous", "none", "null", "unknown", "local"] {
            assert!(
                !is_valid_extracted_user(name, "contoso.local"),
                "should reject: {name}"
            );
        }
    }

    #[test]
    fn is_valid_extracted_user_rejects_underscore_domain() {
        assert!(!is_valid_extracted_user("alice", "_contoso.local"));
    }

    #[test]
    fn is_valid_extracted_user_rejects_long_netbios() {
        // NetBIOS names > 15 chars without a dot are invalid
        assert!(!is_valid_extracted_user("alice", "TOOLONGNETBIOSNAME"));
    }

    #[test]
    fn extract_users_domain_backslash() {
        let users = extract_users("CONTOSO\\alice (SidTypeUser)", "contoso.local");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "alice");
        assert_eq!(users[0].domain, "CONTOSO");
    }

    #[test]
    fn extract_users_upn_format() {
        let users = extract_users("bob@contoso.local", "contoso.local");
        assert!(users.iter().any(|u| u.username == "bob"));
    }

    #[test]
    fn extract_users_skips_machine_accounts() {
        let users = extract_users("CONTOSO\\DC01$", "contoso.local");
        assert!(users.is_empty());
    }

    #[test]
    fn extract_users_empty_output() {
        assert!(extract_users("", "contoso.local").is_empty());
    }

    // --- is_machine_hostname_domain ---

    #[test]
    fn machine_hostname_win_prefix() {
        assert!(is_machine_hostname_domain("WIN-G7FPA5ZZXZV"));
        assert!(is_machine_hostname_domain("win-abc123"));
    }

    #[test]
    fn machine_hostname_win_fqdn() {
        assert!(is_machine_hostname_domain("win-g7fpa5zzxzv.w5an.local"));
        assert!(is_machine_hostname_domain("WIN-ABC123.contoso.local"));
    }

    #[test]
    fn machine_hostname_desktop_prefix() {
        assert!(is_machine_hostname_domain("DESKTOP-ABC1234"));
        assert!(is_machine_hostname_domain("desktop-xyz.corp.local"));
    }

    #[test]
    fn real_domain_not_machine_hostname() {
        assert!(!is_machine_hostname_domain("contoso.local"));
        assert!(!is_machine_hostname_domain("north.sevenkingdoms.local"));
        assert!(!is_machine_hostname_domain("NORTH"));
        assert!(!is_machine_hostname_domain("SEVENKINGDOMS"));
    }

    // --- extract_users with machine hostname filtering ---

    #[test]
    fn extract_users_smb_banner_machine_domain_ignored() {
        // SMB banner with Kali machine domain should not override default_domain
        let output = concat!(
            "SMB  192.168.56.10  445  KINGSLANDING  (domain:WIN-G7FPA5ZZXZV) ...\n",
            "user:[samwell.tarly] rid:[0x44e]\n",
        );
        let users = extract_users(output, "north.sevenkingdoms.local");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "samwell.tarly");
        // Should use default_domain, not the machine hostname
        assert_eq!(users[0].domain, "north.sevenkingdoms.local");
    }

    #[test]
    fn extract_users_upn_machine_domain_substituted() {
        // UPN with machine FQDN should substitute default_domain
        let output = "samwell.tarly@win-g7fpa5zzxzv.w5an.local\n";
        let users = extract_users(output, "north.sevenkingdoms.local");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].username, "samwell.tarly");
        assert_eq!(users[0].domain, "north.sevenkingdoms.local");
    }

    #[test]
    fn extract_users_real_upn_preserved() {
        // Real UPN should keep its domain
        let output = "samwell.tarly@north.sevenkingdoms.local\n";
        let users = extract_users(output, "north.sevenkingdoms.local");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].domain, "north.sevenkingdoms.local");
    }
}
