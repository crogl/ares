//! Parser for `enumerate_domain_trusts` (ldapsearch trustedDomain) output.

use serde_json::{json, Value};

/// LDAP trustDirection values (MS-ADTS 6.1.6.7.9).
const TRUST_DIRECTION_INBOUND: u32 = 1;
const TRUST_DIRECTION_OUTBOUND: u32 = 2;
const TRUST_DIRECTION_BIDIRECTIONAL: u32 = 3;

/// LDAP trustType values (MS-ADTS 6.1.6.7.10).
const TRUST_TYPE_PARENT_CHILD: u32 = 1; // same forest
const TRUST_TYPE_TREE_ROOT: u32 = 2; // tree root (also intra-forest)

/// LDAP trustAttributes (MS-ADTS 6.1.6.7.9) flags.
const TRUST_ATTR_FOREST_TRANSITIVE: u32 = 0x00000008;
const TRUST_ATTR_WITHIN_FOREST: u32 = 0x00000020;
const TRUST_ATTR_QUARANTINED_DOMAIN: u32 = 0x00000004;

/// Parse `enumerate_domain_trusts` ldapsearch output into TrustInfo-compatible JSON values.
///
/// Returns JSON objects matching the `TrustInfo` schema:
/// `{ "domain", "flat_name", "direction", "trust_type", "sid_filtering" }`
pub fn parse_domain_trusts(output: &str) -> Vec<Value> {
    let mut results = Vec::new();

    let mut cn = String::new();
    let mut trust_direction: u32 = 0;
    let mut trust_type: u32 = 0;
    let mut trust_attributes: u32 = 0;
    let mut flat_name = String::new();

    let flush = |cn: &str,
                 trust_direction: u32,
                 trust_type: u32,
                 trust_attributes: u32,
                 flat_name: &str|
     -> Option<Value> {
        if cn.is_empty() {
            return None;
        }

        let direction = match trust_direction {
            TRUST_DIRECTION_INBOUND => "inbound",
            TRUST_DIRECTION_OUTBOUND => "outbound",
            TRUST_DIRECTION_BIDIRECTIONAL => "bidirectional",
            _ => "unknown",
        };

        let classified_type = classify_trust_type(trust_type, trust_attributes, cn);

        // Modern AD defaults to SID filtering on cross-forest/external trusts,
        // but `netdom trust /SidFiltering /Disable` is a common lab and
        // production reconfiguration with no corresponding LDAP attribute. The
        // only authoritative LDAP-visible signal that filtering is *on* is the
        // QUARANTINED_DOMAIN bit, which AD sets when a trust has been
        // explicitly quarantined. Inferring filtering from FOREST_TRANSITIVE
        // alone (or from classified_type) is a false-positive that
        // permanently suppresses `forge_inter_realm_and_dump` against any
        // misconfigured cross-forest trust — losing the entire foreign forest
        // (the op-20260502-185055 fabrikam regression). The forge's
        // dedup-on-empty-output path already handles the false-negative case
        // (~30s doomed DCSync, then dedup locks and fallbacks fire).
        let sid_filtering = trust_attributes & TRUST_ATTR_QUARANTINED_DOMAIN != 0;

        Some(json!({
            "domain": cn.to_lowercase(),
            "flat_name": flat_name,
            "direction": direction,
            "trust_type": classified_type,
            "sid_filtering": sid_filtering,
        }))
    };

    for line in output.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') {
            if let Some(trust) = flush(
                &cn,
                trust_direction,
                trust_type,
                trust_attributes,
                &flat_name,
            ) {
                results.push(trust);
            }
            cn.clear();
            trust_direction = 0;
            trust_type = 0;
            trust_attributes = 0;
            flat_name.clear();
            continue;
        }

        if line.starts_with("dn:") || line.starts_with("objectClass:") {
            continue;
        }

        if let Some(val) = line.strip_prefix("cn: ") {
            cn = val.trim().to_string();
        } else if let Some(val) = line.strip_prefix("trustDirection: ") {
            trust_direction = val.trim().parse().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("trustType: ") {
            trust_type = val.trim().parse().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("trustAttributes: ") {
            trust_attributes = val.trim().parse().unwrap_or(0);
        } else if let Some(val) = line.strip_prefix("flatName: ") {
            flat_name = val.trim().to_string();
        }
    }

    // Flush last block
    if let Some(trust) = flush(
        &cn,
        trust_direction,
        trust_type,
        trust_attributes,
        &flat_name,
    ) {
        results.push(trust);
    }

    results
}

/// Classify trust type from LDAP trustType and trustAttributes values.
///
/// trustAttributes is the authoritative signal:
/// - WITHIN_FOREST (0x20) → intra-forest (parent_child or tree_root)
/// - FOREST_TRANSITIVE (0x08) → cross-forest
/// - QUARANTINED_DOMAIN (0x04) → external (with SID filtering)
///
/// trustType is largely informational in modern AD (almost always 2 = uplevel).
/// Fall back to cn-label heuristics only when attributes are missing.
fn classify_trust_type(trust_type: u32, trust_attributes: u32, cn: &str) -> String {
    // Authoritative attribute checks first.
    if trust_attributes & TRUST_ATTR_WITHIN_FOREST != 0 {
        return "parent_child".to_string();
    }
    if trust_attributes & TRUST_ATTR_FOREST_TRANSITIVE != 0 {
        return "forest".to_string();
    }
    if trust_attributes & TRUST_ATTR_QUARANTINED_DOMAIN != 0 {
        return "external".to_string();
    }

    // Fall back to legacy trustType-based heuristics.
    match trust_type {
        TRUST_TYPE_PARENT_CHILD => "parent_child".to_string(),
        TRUST_TYPE_TREE_ROOT => {
            let parts: Vec<&str> = cn.split('.').collect();
            if parts.len() >= 3 {
                "parent_child".to_string()
            } else {
                "forest".to_string()
            }
        }
        _ => "external".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cross_forest_trust() {
        let output = r#"dn: CN=fabrikam.local,CN=System,DC=contoso,DC=local
cn: fabrikam.local
trustDirection: 3
trustType: 2
trustAttributes: 8
flatName: FABRIKAM
"#;
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0]["domain"], "fabrikam.local");
        assert_eq!(trusts[0]["flat_name"], "FABRIKAM");
        assert_eq!(trusts[0]["direction"], "bidirectional");
        assert_eq!(trusts[0]["trust_type"], "forest");
        // FOREST_TRANSITIVE (0x08) alone does NOT imply SID filtering — only
        // QUARANTINED_DOMAIN (0x04) is authoritative. See parse_domain_trusts.
        assert!(!trusts[0]["sid_filtering"].as_bool().unwrap());
    }

    #[test]
    fn parse_parent_child_trust() {
        let output = r#"dn: CN=north.contoso.local,CN=System,DC=contoso,DC=local
cn: north.contoso.local
trustDirection: 3
trustType: 1
trustAttributes: 0
flatName: CHILD
"#;
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0]["domain"], "north.contoso.local");
        assert_eq!(trusts[0]["trust_type"], "parent_child");
        assert!(!trusts[0]["sid_filtering"].as_bool().unwrap());
    }

    #[test]
    fn parse_multiple_trusts() {
        let output = r#"dn: CN=fabrikam.local,CN=System,DC=contoso,DC=local
cn: fabrikam.local
trustDirection: 3
trustType: 2
trustAttributes: 8
flatName: FABRIKAM

dn: CN=north.contoso.local,CN=System,DC=contoso,DC=local
cn: north.contoso.local
trustDirection: 3
trustType: 1
trustAttributes: 0
flatName: CHILD
"#;
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 2);
        assert_eq!(trusts[0]["trust_type"], "forest");
        assert_eq!(trusts[1]["trust_type"], "parent_child");
    }

    #[test]
    fn parse_inbound_trust() {
        let output =
            "cn: partner.com\ntrustDirection: 1\ntrustType: 3\ntrustAttributes: 0\nflatName: PARTNER\n";
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0]["direction"], "inbound");
        assert_eq!(trusts[0]["trust_type"], "external");
    }

    #[test]
    fn parse_empty_output() {
        let trusts = parse_domain_trusts("");
        assert!(trusts.is_empty());
    }

    #[test]
    fn parse_no_trusts_search_result() {
        let output = "# search result\nsearch: 2\nresult: 0 Success\n";
        let trusts = parse_domain_trusts(output);
        assert!(trusts.is_empty());
    }

    #[test]
    fn parse_outbound_trust() {
        let output = "cn: external.com\ntrustDirection: 2\ntrustType: 3\ntrustAttributes: 0\nflatName: EXTERNAL\n";
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0]["direction"], "outbound");
        assert_eq!(trusts[0]["trust_type"], "external");
        // Without QUARANTINED_DOMAIN we don't infer SID filtering — labs and
        // misconfigured prod often have it disabled and there's no other
        // LDAP-visible signal. The forge will attempt and dedup-on-empty if
        // filtering is actually on.
        assert!(!trusts[0]["sid_filtering"].as_bool().unwrap());
    }

    #[test]
    fn parse_trust_unknown_direction() {
        let output = "cn: mystery.local\ntrustDirection: 99\ntrustType: 1\ntrustAttributes: 0\nflatName: MYSTERY\n";
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0]["direction"], "unknown");
    }

    #[test]
    fn parse_trust_tree_root_short_domain() {
        // trustType=2 with short domain (< 3 labels) → forest
        let output = "cn: fabrikam.com\ntrustDirection: 3\ntrustType: 2\ntrustAttributes: 0\nflatName: FABRIKAM\n";
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0]["trust_type"], "forest");
    }

    #[test]
    fn parse_trust_tree_root_long_domain() {
        // trustType=2 with 3+ labels → parent_child
        let output = "cn: child.contoso.local\ntrustDirection: 3\ntrustType: 2\ntrustAttributes: 0\nflatName: CHILD\n";
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0]["trust_type"], "parent_child");
    }

    #[test]
    fn parse_trust_within_forest_from_child_view() {
        // When enumerating from child looking up to parent, cn is short
        // ("contoso.local") but trustAttributes has WITHIN_FOREST (0x20).
        // The attribute is authoritative and should yield parent_child.
        let output =
            "cn: contoso.local\ntrustDirection: 3\ntrustType: 2\ntrustAttributes: 32\nflatName: CONTOSO\n";
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0]["trust_type"], "parent_child");
        assert!(!trusts[0]["sid_filtering"].as_bool().unwrap());
    }

    #[test]
    fn parse_trust_quarantined_external() {
        // QUARANTINED_DOMAIN (0x04) → external trust with SID filtering.
        let output =
            "cn: partner.com\ntrustDirection: 3\ntrustType: 2\ntrustAttributes: 4\nflatName: PARTNER\n";
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts.len(), 1);
        assert_eq!(trusts[0]["trust_type"], "external");
        assert!(trusts[0]["sid_filtering"].as_bool().unwrap());
    }

    #[test]
    fn parse_trust_domain_lowercased() {
        let output = "cn: FABRIKAM.LOCAL\ntrustDirection: 3\ntrustType: 2\ntrustAttributes: 8\nflatName: FABRIKAM\n";
        let trusts = parse_domain_trusts(output);
        assert_eq!(trusts[0]["domain"], "fabrikam.local");
    }
}
