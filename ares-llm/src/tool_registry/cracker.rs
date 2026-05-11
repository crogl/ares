//! Cracker role tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub(super) fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "crack_with_hashcat".into(),
            description: "Crack password hashes using hashcat with GPU acceleration. Supports \
                Kerberos TGS-REP, AS-REP, NTLM, and other hash types. Automatically selects \
                rules and wordlists when use_dynamic_wordlist is enabled."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "hash_value": {
                        "type": "string",
                        "description": "The hash to crack (raw hash string or path to a file containing hashes)"
                    },
                    "hashcat_mode": {
                        "type": "integer",
                        "description": "Hashcat hash mode. Common modes: 13100=Kerberos TGS-REP (Kerberoasting), 18200=Kerberos AS-REP (ASREPRoasting), 1000=NTLM, 5600=NetNTLMv2, 3000=LM. Defaults to 13100.",
                        "default": 13100
                    },
                    "wordlist_path": {
                        "type": "string",
                        "description": "Path to a custom wordlist file. If omitted, the default wordlist (e.g. rockyou.txt) is used."
                    },
                    "rules_file": {
                        "type": "string",
                        "description": "Path to a hashcat rules file (e.g. /usr/share/hashcat/rules/best64.rule). If omitted, default rules (best64 + d3ad0ne) are applied automatically after the straight wordlist phase."
                    },
                    "max_time_minutes": {
                        "type": "integer",
                        "description": "Maximum time in minutes before aborting the crack attempt. Defaults to 20. Do NOT set below 20 — CPU-only cracking needs time to traverse large wordlists.",
                        "default": 20
                    },
                    "use_dynamic_wordlist": {
                        "type": "boolean",
                        "description": "When true, augments the wordlist with username-derived password candidates (e.g. john.smith -> John, Smith, john1, Smith123). Defaults to true.",
                        "default": true
                    },
                    "known_usernames": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "List of known usernames from the target domain, used to generate dynamic password candidates. Pass all discovered usernames for best coverage."
                    }
                },
                "required": ["hash_value"]
            }),
        },
        ToolDefinition {
            name: "crack_with_john".into(),
            description: "Crack password hashes using John the Ripper. Supports Kerberos, NTLM, \
                and other formats. Useful as a fallback when hashcat GPU cracking is unavailable \
                or for formats better handled by JtR."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "hash_value": {
                        "type": "string",
                        "description": "The hash to crack (raw hash string or path to a file containing hashes)"
                    },
                    "hash_format": {
                        "type": "string",
                        "description": "John the Ripper hash format name. Common formats: krb5tgs (Kerberoasting), krb5asrep (ASREPRoasting), nt (NTLM), netntlmv2 (NetNTLMv2). Defaults to krb5tgs.",
                        "default": "krb5tgs"
                    },
                    "wordlist_path": {
                        "type": "string",
                        "description": "Path to a custom wordlist file. If omitted, the default wordlist is used."
                    },
                    "max_time_minutes": {
                        "type": "integer",
                        "description": "Maximum time in minutes before aborting the crack attempt. Defaults to 20. Do NOT set below 20 — CPU-only cracking needs time to traverse large wordlists.",
                        "default": 20
                    },
                    "use_dynamic_wordlist": {
                        "type": "boolean",
                        "description": "When true, augments the wordlist with username-derived password candidates. Defaults to true.",
                        "default": true
                    },
                    "known_usernames": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "List of known usernames from the target domain, used to generate dynamic password candidates."
                    }
                },
                "required": ["hash_value"]
            }),
        },
    ]
}

pub(super) fn callback_definitions() -> Vec<ToolDefinition> {
    vec![
        // Re-added as a structured fallback. The preferred path is still
        // auto-extraction from raw hashcat/john stdout in `output_extraction.rs`
        // — that's lossless and doesn't trust LLM-generated values. But the
        // cracker LLM agent has been observed reporting its result as natural-
        // language text ("password = fr3edom") without piping the raw
        // `--show` line into `tool_outputs`, leaving the extraction regex with
        // nothing to match. When that happens, the cracked plaintext is lost.
        // This callback gives the LLM an unambiguous structured channel so the
        // cleartext lands in `state.credentials` even when the raw stdout path
        // misses. The handler validates `password` through `is_valid_credential`
        // (rejecting hash-shaped strings, truncation ellipsis, etc.), so the
        // LLM can't pollute credentials with fabricated values.
        ToolDefinition {
            name: "report_cracked_credential".into(),
            description: "Report a successfully cracked credential from hashcat or john output. \
                Use this ONLY after a cracker tool has emitted the actual cleartext password — \
                pass the exact plaintext from `hashcat --show` / `john --show` output. The system \
                will store the resulting credential and annotate the corresponding hash. \
                Do NOT use this for hashes you haven't actually cracked, or for guessed/inferred \
                passwords — the validator rejects anything that looks like a hash or a truncated \
                display string."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username the cracked plaintext belongs to (no domain prefix)."
                    },
                    "domain": {
                        "type": "string",
                        "description": "FQDN of the domain the user belongs to (e.g. 'contoso.local')."
                    },
                    "password": {
                        "type": "string",
                        "description": "Cleartext password as printed by the cracker. Must NOT contain '...' (LLM truncation) or look like a hash."
                    },
                    "hash_type": {
                        "type": "string",
                        "description": "Hash type that was cracked (e.g. 'asrep', 'kerberoast', 'ntlm')."
                    },
                    "task_id": {
                        "type": "string",
                        "description": "The cracking task ID this credential was produced from."
                    }
                },
                "required": ["username", "domain", "password"]
            }),
        },
        ToolDefinition {
            name: "report_crack_failed".into(),
            description: "Report that a cracking attempt failed and no password was recovered. \
                This allows the orchestrator to update task status and potentially retry with \
                different parameters or a larger wordlist."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "task_id": {
                        "type": "string",
                        "description": "The task ID associated with this cracking job"
                    },
                    "hash_value": {
                        "type": "string",
                        "description": "The hash value that could not be cracked"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason the cracking failed (e.g. exhausted wordlist, timeout, unsupported format). Defaults to 'exhausted wordlist'.",
                        "default": "exhausted wordlist"
                    }
                },
                "required": ["task_id", "hash_value"]
            }),
        },
    ]
}
