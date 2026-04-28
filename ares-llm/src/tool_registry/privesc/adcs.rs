//! ADCS / Certipy tool definitions.

use serde_json::json;

use crate::ToolDefinition;

pub fn definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "certipy_find".into(),
            description: "Find vulnerable certificate templates in Active Directory Certificate \
                Services (AD CS). Enumerates CAs, templates, and identifies exploitable \
                misconfigurations (ESC1-ESC15)."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. contoso.local)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "hashes": {
                        "type": "string",
                        "description": "NTLM hash for pass-the-hash (format: 'lmhash:nthash' or just ':nthash'). Use instead of password."
                    },
                    "vulnerable": {
                        "type": "boolean",
                        "description": "Only show vulnerable templates. Defaults to true.",
                        "default": true
                    }
                },
                "required": ["domain", "username", "dc_ip"]
            }),
        },
        ToolDefinition {
            name: "certipy_request".into(),
            description: "Request a certificate from AD CS using a specific CA and template. \
                Used to exploit vulnerable templates (e.g. ESC1) to obtain certificates for \
                privileged accounts."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. contoso.local)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "ca": {
                        "type": "string",
                        "description": "Certificate Authority name (e.g. 'contoso-DC01-CA')"
                    },
                    "template": {
                        "type": "string",
                        "description": "Certificate template name to request"
                    },
                    "upn": {
                        "type": "string",
                        "description": "User Principal Name to request the certificate for. Defaults to Administrator.",
                        "default": "Administrator"
                    },
                    "target": {
                        "type": "string",
                        "description": "CA server IP or hostname to connect to for certificate enrollment. REQUIRED when the CA is on a different host than the DC (e.g. CA on a member server, DC on the domain controller). Without this, certipy tries RPC on the DC which fails with ept_s_not_registered."
                    },
                    "sid": {
                        "type": "string",
                        "description": "Object SID to embed in the certificate (e.g. 'S-1-5-21-...-500' for Administrator). Required by certipy v5+ to prevent SID mismatch errors during certipy_auth. For Administrator, use the domain SID + '-500'."
                    },
                    "out": {
                        "type": "string",
                        "description": "Output filename for the PFX certificate (without .pfx extension). A unique name is auto-generated if not specified. The resulting file will be <out>.pfx — use this path for certipy_auth's pfx_path parameter."
                    },
                    "application_policies": {
                        "type": "string",
                        "description": "Application policy OID to include in the certificate request. Used for ESC15 (CVE-2024-49019) exploitation where the template uses application policy OIDs for authorization."
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "ca", "template"]
            }),
        },
        ToolDefinition {
            name: "certipy_auth".into(),
            description: "Authenticate to Active Directory using a PFX certificate file. \
                Performs PKINIT Kerberos authentication and retrieves the NT hash of the \
                certificate's subject."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. contoso.local)"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "pfx_path": {
                        "type": "string",
                        "description": "Path to the PFX certificate file"
                    }
                },
                "required": ["domain", "dc_ip", "pfx_path"]
            }),
        },
        ToolDefinition {
            name: "certipy_shadow".into(),
            description: "Exploit Shadow Credentials by adding a Key Credential to a target \
                account's msDS-KeyCredentialLink attribute via Certipy, then authenticating \
                with the resulting certificate."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. contoso.local)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication (must have write access to target)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "target": {
                        "type": "string",
                        "description": "Target account to add shadow credentials to"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "target"]
            }),
        },
        ToolDefinition {
            name: "certipy_template_esc4".into(),
            description: "Modify a vulnerable certificate template for ESC4 exploitation. \
                Overwrites template attributes to allow enrollment and subject alternative \
                name specification."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. contoso.local)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication (must have write access to template)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "template": {
                        "type": "string",
                        "description": "Certificate template name to modify"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "template"]
            }),
        },
        ToolDefinition {
            name: "certipy_esc4_full_chain".into(),
            description: "Execute the full ESC4 exploit chain: modify a vulnerable certificate \
                template, request a certificate for a privileged user, and authenticate with \
                the resulting certificate to obtain NT hashes."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. contoso.local)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication (must have write access to template)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "template": {
                        "type": "string",
                        "description": "Certificate template name to exploit"
                    },
                    "ca": {
                        "type": "string",
                        "description": "Certificate Authority name (e.g. 'contoso-DC01-CA')"
                    },
                    "target_upn": {
                        "type": "string",
                        "description": "UPN of the target user to impersonate. Defaults to Administrator.",
                        "default": "Administrator"
                    },
                    "target": {
                        "type": "string",
                        "description": "CA server IP or hostname for certificate enrollment. REQUIRED when the CA is on a different host than the DC."
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "template", "ca"]
            }),
        },
        ToolDefinition {
            name: "certipy_ca".into(),
            description: "Manage a Certificate Authority using Certipy. Can add yourself as a \
                CA officer (ManageCA right required) or issue a pending certificate request."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. contoso.local)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication (must have ManageCA rights)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "ca": {
                        "type": "string",
                        "description": "Certificate Authority name (e.g. 'CONTOSO-CA')"
                    },
                    "add_officer": {
                        "type": "boolean",
                        "description": "Add yourself as a CA officer. Requires ManageCA rights."
                    },
                    "issue_request": {
                        "type": "integer",
                        "description": "Issue (approve) a pending certificate request by its request ID."
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "ca"]
            }),
        },
        ToolDefinition {
            name: "certipy_retrieve".into(),
            description: "Retrieve a previously issued certificate from the CA by its request ID. \
                Used after certipy_ca -issue-request approves a pending request."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. contoso.local)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "ca": {
                        "type": "string",
                        "description": "Certificate Authority name"
                    },
                    "request_id": {
                        "type": "integer",
                        "description": "The certificate request ID to retrieve"
                    },
                    "target": {
                        "type": "string",
                        "description": "CA server IP or hostname for RPC enrollment"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "ca", "request_id"]
            }),
        },
        ToolDefinition {
            name: "certipy_relay".into(),
            description: "Start a Certipy relay listener for ADCS certificate enrollment via \
                relay attacks. Supports HTTP relay (ESC8) and RPC relay (ESC11). \
                For ESC8: target=http://ca-host. For ESC11: target=rpc://ca-host."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Relay target URL. Use 'http://<ca-host>' for ESC8 (HTTP web enrollment relay) or 'rpc://<ca-host>' for ESC11 (RPC certificate enrollment relay)."
                    },
                    "ca": {
                        "type": "string",
                        "description": "Certificate Authority name (e.g. 'CONTOSO-CA')"
                    },
                    "template": {
                        "type": "string",
                        "description": "Certificate template to request during relay. Optional — defaults to Machine for HTTP or uses the CA's default."
                    }
                },
                "required": ["target", "ca"]
            }),
        },
        ToolDefinition {
            name: "certipy_esc7_full_chain".into(),
            description: "Execute the full ESC7 exploit chain: add yourself as CA officer \
                (ManageCA abuse), request a SubCA certificate (gets denied), issue the pending \
                request, retrieve the certificate, and authenticate to obtain NT hashes. \
                Requires the user to have ManageCA rights on the target CA."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "Target domain (e.g. contoso.local)"
                    },
                    "username": {
                        "type": "string",
                        "description": "Username for authentication (must have ManageCA rights)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password for authentication"
                    },
                    "dc_ip": {
                        "type": "string",
                        "description": "Domain controller IP address"
                    },
                    "ca": {
                        "type": "string",
                        "description": "Certificate Authority name (e.g. 'CONTOSO-CA')"
                    },
                    "target": {
                        "type": "string",
                        "description": "CA server IP or hostname for certificate enrollment. REQUIRED when the CA is on a different host than the DC."
                    },
                    "upn": {
                        "type": "string",
                        "description": "UPN of the user to impersonate. Defaults to 'administrator@<domain>'.",
                        "default": "administrator"
                    },
                    "sid": {
                        "type": "string",
                        "description": "SID to embed in the certificate (e.g. domain SID + '-500' for Administrator)"
                    }
                },
                "required": ["domain", "username", "password", "dc_ip", "ca"]
            }),
        },
    ]
}
