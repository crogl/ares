use std::collections::{HashMap, HashSet};

use ares_core::models::Hash;

use super::credentials::strip_ansi;
use super::{is_ghost_machine_account, strip_trailing_dot};

fn normalize_hash_type(hash_type: &str) -> String {
    match hash_type.trim().to_lowercase().as_str() {
        "ntlm" => "NTLM".to_string(),
        "kerberoast" => "Kerberoast".to_string(),
        "asrep" | "as-rep" | "asreproast" => "AS-REP".to_string(),
        "aes256" | "aes-256" => "AES256".to_string(),
        "aes128" | "aes-128" => "AES128".to_string(),
        other => other.to_string(),
    }
}

pub(crate) fn dedup_hashes(hashes: &[Hash]) -> Vec<Hash> {
    // First pass: for each (username, hash_type, hash_value), remember the longest
    // non-empty domain we've seen. Parsers sometimes emit the same hash twice — once
    // with `DOMAIN\` prefix (populated domain) and once bare (empty domain) — and
    // without this lookup the keyed-by-domain dedup keeps both as separate rows.
    let mut domain_lookup: HashMap<(String, String, String), String> = HashMap::new();
    for h in hashes {
        let domain = strip_trailing_dot(h.domain.trim()).to_lowercase();
        if domain.is_empty() {
            continue;
        }
        let key = (
            h.username.trim().to_lowercase(),
            h.hash_type.trim().to_lowercase(),
            strip_ansi(&h.hash_value).trim().to_lowercase(),
        );
        domain_lookup
            .entry(key)
            .and_modify(|d| {
                if domain.len() > d.len() {
                    *d = domain.clone();
                }
            })
            .or_insert(domain);
    }

    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for h in hashes {
        let username = strip_ansi(&h.username);
        if is_ghost_machine_account(&username) {
            continue;
        }
        let username_l = h.username.trim().to_lowercase();
        let hash_type_l = h.hash_type.trim().to_lowercase();
        let hash_value = strip_ansi(&h.hash_value);
        let hash_value_l = hash_value.trim().to_lowercase();

        let mut domain = strip_trailing_dot(h.domain.trim()).to_lowercase();
        if domain.is_empty() {
            if let Some(d) = domain_lookup.get(&(
                username_l.clone(),
                hash_type_l.clone(),
                hash_value_l.clone(),
            )) {
                domain.clone_from(d);
            }
        }

        let key = (domain.clone(), username_l, hash_type_l, hash_value_l);
        if seen.insert(key) {
            let mut cleaned = h.clone();
            cleaned.domain = domain;
            cleaned.hash_type = normalize_hash_type(&cleaned.hash_type);
            cleaned.hash_value = hash_value.trim().to_string();
            cleaned.username = strip_ansi(&cleaned.username);
            result.push(cleaned);
        }
    }
    result
}
