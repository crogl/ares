# Plan: Close essos.local kill-path + loot display fixes

Headline gap: the orchestrator has every primitive needed to own `essos.local`
(ESSOS$ inter-realm trust key + `missandei:fr3edom` low-priv user + ADCS
topology on ESSOS-CA + MSSQL impersonation target + sql_svc Kerberoast hashes)
and refuses to chain them. Several display/ingestion bugs make this state hard
to read. Plan groups by execution priority: close the kill-path first, then fix
display.

Line numbers below come from explorer agents; re-confirm at the keyboard before
editing — `trust.rs`, `adcs_exploitation.rs`, `mssql_link_pivot.rs`, and the
credential resolver are all dirty in `git status` and have drifted.

---

## Status board (for multi-agent coordination)

Legend: `[ ]` open · `[~]` in progress (with owner) · `[x]` done

**Claim a row before starting work.** Update this table when you start, finish,
or hand off. Branch per row; PRs land in PR-number order so PR 0 lands first.

| Item    | Owner       | Status | Notes |
|---------|-------------|--------|-------|
| Phase 0 step 1 — trust.rs gate    | claude-opus | `[x]`  | `auto_trust_follow` L210; gate `.cloned()?` L1296; insert Tier-1.5 at L1283. Impacket bash -c already satisfied via `expand_technique_task` (L1470-1474) — no chain rewrite needed in PR 1. |
| Phase 0 step 2 — adcs ESC1 hardcoded admin | claude-opus | `[x]`  | ESC1 deterministic uses `format!("administrator@{}", item.domain)` at L634; cred selection (L155-186) has NO privilege gate today — any domain user passes. **PR 2 likely subsumed by PR 0** — if missandei isn't being used, it's the cred-resolver match failing on domain casing/FQDN form, not a privilege check. Re-scope PR 2 after PR 0 lands. No inter-realm `-k` path exists in this file. |
| Phase 0 step 3 — credential_resolver case-sensitivity | claude-opus | `[x]`  | **Plan was wrong.** Domain compare at L703 already lowercases both sides. No `find_trust_credential` exists — fallback is internal `any_user` bucket (L711-715), already fires on non-empty-domain misses for non-Administrator/Guest/krbtgt users. **Real remaining gap**: NetBIOS short-form ("NORTH") doesn't match FQDN ("north.sevenkingdoms.local"). Reuse existing `resolve_domain(domain, netbios_map)` at `ares-cli/src/orchestrator/recovery/normalize.rs:9` — don't duplicate. PR 0 scope shrinks. |
| Phase 0 step 4 — Hash/Share field lists | claude-opus | `[x]`  | `Hash` at `ares-core/src/models/core.rs:125-148` (no metadata bag, none of `is_previous`/`is_trust_key`/`trust_pair_label`/`source_host` exist); `Share` at L607-615 (no `authenticated_as`). New fields need `#[serde(default)]` for back-compat. `dedup_hashes` at `ares-core/src/reports/dedup.rs:38-50` keys on `(domain, username, hash_value)` — must explicitly add `source_host` to key. |
| Phase 0 step 5 — secretsdump source-host seam | claude-opus | `[x]`  | **Dispatcher seam wins.** Parser strips host. `task_target_ip` is in scope at `result_processing/mod.rs:56-71`, available at `publish_hash` call sites L740, L898. `discovery_polling.rs:119` (third caller) has no context, passes `None`. Set `Hash.source_host` before `publish_hash` — do not change `publish_hash` signature (model field travels naturally). |
| Phase 0 step 6 — kerberoast → Hash path | claude-opus | `[x]`  | **Pipeline already exists end-to-end.** Parser at `ares-tools/src/parsers/secrets.rs:233` emits Hash with `hash_type: "kerberoast"`; routed in `parsers/mod.rs:132-135`; deserialized in `result_processing/parsing.rs:95-100`; published in `result_processing/mod.rs:891-913`; `crack.rs:25-28` prioritizes kerberoast at priority 0 (highest). **PR 4 is not needed as code work** — the operator's raw sql_svc hashes are an operational/diagnosis issue (wordlist? worker capacity? not coming through the kerberoast tool dispatch?). |
| PR 0 — Phase 1G (NetBIOS↔FQDN equivalence) | claude-opus | `[x]`  | **Code done.** In `resolve_credentials`: load `netbios_map` via `reader.get_netbios_map`, normalize stored creds/hashes via `normalize_*_domains`, normalize the resolved `primary_domain` via `resolve_domain` after both arg- and infer- paths. Made `crate::orchestrator::recovery` `pub(crate)`. Two new unit tests (`find_credential_netbios_form_matches_after_normalize`, `find_credential_normalize_noop_when_map_empty`). All 10 `find_credential` tests pass. Not yet committed. |
| PR 1 — Phase 1A/1B (trust kill-path) | claude-opus | `[x]`  | **Code done.** 1A: `resolve_target_fqdn_from_signals` in `trust.rs` (Tier-1.5 corroborated-signal FQDN resolution from hosts/credentials/discovered_vulns); 7 unit tests including 4 negative regression guards. 1B: `is_previous: bool` field on `Hash` (with `#[serde(default)]`); `strip_history_suffix` in `secrets.rs` detects `_history<N>` and `_prev` suffixes; trust hash iteration in `auto_trust_follow` now sorts current-first so dedup prefers current key. Updated all 30+ Hash construction sites across workspace. `cargo check --workspace --tests` green; 36/36 trust tests + 4 new parser tests pass. Not yet committed. |
| PR 2 — Phase 1C (ADCS low-priv authenticator) | _re-scope_ | `[?]` | Phase 0 step 2 shows no privilege gate exists; likely subsumed by PR 0. Re-evaluate after PR 0 lands and missandei is observed authenticating. |
| PR 3 — Phase 1D/1E (MSSQL impersonation + linked-server) | claude-sub-a67299d3 + opus follow-up | `[x]` | `auto_mssql_impersonation` added in `automation/mssql_exploitation.rs`; link-pivot gate in `collect_pivot_work` now fires on same-target exploited `mssql_impersonation`; new dedup set `DEDUP_MSSQL_IMPERSONATION`. **Follow-up fix landed**: sub-agent originally set `impersonate_user = account_name` (no-op EXECUTE AS LOGIN). Verified at `ares-tools/src/parsers/mssql.rs:67` that `account_name` is the _impersonator_ (auth user), not the target. Impersonate target now hardcoded to `"sa"` via `IMPERSONATION_TARGET_LOGIN`. Two tests updated. 16/16 mssql tests pass, workspace check clean. Not committed. |
| PR 4 — Phase 1F (Kerberoast/crack retry cap) | claude-opus | `[x]` | **Code done.** Added `crack_attempts: HashMap<String, u32>` to `StateInner` + `MAX_CRACK_ATTEMPTS = 3` const in `crack.rs`. `auto_crack_dispatch` increments the counter on dispatch and marks `DEDUP_CRACK_REQUESTS` only when the counter hits the cap (was: marked unconditionally on dispatch success). Result: a hashcat exit ≠ 0 (wordlist miss, transient crash) no longer permanently strands the hash — it gets up to 3 attempts before permanent skip. `credential_access.rs` unchanged (its `DEDUP_CRACK_REQUESTS` keys are structurally distinct from `crack.rs`'s, so they don't collide). 3 new unit tests pin state invariants: below-cap doesn't write dedup, at-cap writes permanently, per-hash independence. 5170/5170 workspace tests green. To confirm on live op: `SMEMBERS ares:op:{op-id}:dedup:crack_requests` will only contain capped hashes, not in-flight failures. Not committed. |
| PR 5 — Phase 2 (loot/report schema + renderer) | claude-opus | `[x]` | Hash schema +`source_host`/`is_trust_key`/`trust_pair_label`; Share +`authenticated_as`; `secretsdump_implicit` user backfill in `publish_hash`; `dedup_hashes` keyed on canonical domain + source_host; secretsdump parser tags trust-key rows (with `classify_trust_key` helper); per-detail vuln truncation at 100 chars + ellipsis; comprehensive template renames "Credentials"→"Cracked Plaintext", "Hashes"→"Hash Material (Pass-the-Hash usable)", adds "Trust Keys / Forging Material" section with symmetric-pair badge + current/previous tag, adds Auth column to shares; 12 new unit tests (4 trust-key parser, 3 dedup source_host, 2 symmetric pair, 4 vuln truncation). 5167/5167 workspace tests green; not committed. |

---

## Phase 0 — Verification (30 min, before any code)

Confirm explorer findings against current HEAD.

1. `ares-cli/src/orchestrator/automation/trust.rs` — locate `auto_trust_follow`,
   the trust-account hash filter loop (~1250), and the `domain_controllers` /
   `dominated_domains` fallback (~1284-1296). Confirm a target with no prior
   trust-enum row is silently dropped at `.cloned()?`.
2. `ares-cli/src/orchestrator/automation/adcs_exploitation.rs` — confirm ESC1
   hardcodes `impersonate=administrator` in `dispatch_esc1_deterministic`
   (`certipy_esc1_full_chain` call site).
3. `ares-cli/src/worker/credential_resolver.rs::find_credential` — confirm
   case-sensitive domain compare and absence of empty-domain fallback to
   `find_trust_credential`.
4. `ares-core/src/models/core.rs` — confirm exact `Hash` and `Share` field lists.
   The explorer's line numbers may be off; we'll be adding fields here.
5. **Secretsdump source-host seam (for 2.8):** run a sample `secretsdump.py
   user@host` and inspect stdout. Does the tool emit the source host in the
   output, or is it only implicit from the invocation? If implicit (likely),
   thread `source_host` through the dispatcher context — not the parser.
   Locate the dispatch call site that wraps `secretsdump` and confirm the
   target hostname/IP is in scope at the point where parsed rows are published
   to state. This decides whether 2.8 patches the parser or the publisher.
6. **Kerberoast → Hash path (for 1F):** the parser/automation modules have
   recent edits (`7ceeac77 feat: harden cracked credential ingestion and asrep
   automation`). Re-confirm there is no existing path from kerberoast tool
   output to a `Hash` record before assuming the fix is "add one." Grep
   `parsers/`, `state/publishing/`, and automation handlers for `krb5tgs` and
   `kerberoast` references.

If any don't match, the plan still holds but specific patch sites shift.

---

## Phase 1 — Close the essos.local kill path (issues #1, #2, #3, #4)

### 1A. Surface inter-realm trust keys as actionable even when target domain unknown

**File:** `ares-cli/src/orchestrator/automation/trust.rs` (trust-account hash
filter inside `auto_trust_follow`).

- Current logic only dispatches `ticketer` when the target domain is already in
  `trusted_domains`, `domain_controllers`, or `dominated_domains`. For
  `essos.local` we have none of those, but we do have the `ESSOS$` hash on the
  sevenkingdoms side, plus host IP `10.1.2.58` and ADCS host `10.1.2.254`
  already known.
- Change: when a hash named `<LABEL>$` lives in source domain D, treat
  `<LABEL>` as a NetBIOS candidate for an outbound trust. Resolve a target FQDN
  by checking, in order:
  1. `trusted_domains`
  2. `domain_controllers` keyed by hostname
  3. **Corroborated signal from existing state.** Accept a candidate FQDN only
     if both hold:
     - The candidate's first DNS label (uppercased) equals the trust-account
       prefix (`ESSOS$` ⇒ candidate must start with `essos.`).
     - At least one corroborating record exists: a `Host` row with hostname
       matching `*.<candidate>` OR a credential row with `domain ==
       <candidate>` OR a vuln entry with `details.domain == <candidate>`.
- **No blind guessing.** If no candidate FQDN is corroborated by existing
  state, do not dispatch — log a skipped-trust event and move on. Operator can
  inject the domain manually via existing inject-state tooling. (This
  explicitly removes the earlier `label.guessed_tld()` fallback.)
- **Impacket constraint:** the forge+secretsdump dispatch MUST be a single
  `bash -c "ticketer ... && secretsdump ..."` command. No ccache persistence
  across `run_tool` calls — splitting into two dispatches drops the forged
  TGT. See CLAUDE.md "Impacket Kerberos Constraints" §4.
- Acceptance: with the loot described, `forest_trust_escalation 10.1.2.58
  essos` fires within one tick — corroboration is satisfied via
  `essos.local\missandei` cred and `meereen.essos.local` hostname both in
  state.

### 1B. Disambiguate current vs previous trust keys (issue #10)

**Files:**

- `ares-tools/src/parsers/` — secretsdump parser (explorer pointed to
  `secrets.rs`; verify path).
- `ares-core/src/models/core.rs` — add `is_previous: bool` to `Hash`.

- Detect `_history0` / `_prev` / `_history1` markers in NTDS rows and stamp the
  hash record. NTDS prints history keys with `_history0`, `_history1`
  suffixes; same for AES variants.
- In 1A, when choosing the ESSOS$ hash to forge with, prefer `is_previous ==
  false`. Fall back to history keys only if the current one fails dispatch.
- In the loot renderer (Phase 2), tag previous keys explicitly.

### 1C. ADCS ESC1 must impersonate Administrator using a low-priv credential

**File:** `ares-cli/src/orchestrator/automation/adcs_exploitation.rs`

- Today the dispatcher rejects ADCS exploitation against a foreign domain when
  no privileged cred is available. ESC1's `dispatch_esc1_deterministic` already
  calls certipy with `-upn administrator` — but the _authenticating_ credential
  needs to be ANY domain user in essos.local, not Administrator.
- Change: the credential-selection path (same-domain / trust-credential
  branches) must accept `missandei:fr3edom` as an authenticating cred for ESC1
  against essos.local. The `upn` (target impersonation) stays `administrator`;
  the auth cred is the low-priv account.
- Verify precondition gate: don't require `state.has_domain_admin` or any
  ownership flag on the target domain. ESC1 specifically does not need
  pre-owned status — only a domain user in the target forest.
- Also expose a path that prefers an inter-realm TGT once 1A succeeds (Kerberos
  auth `-k` against ESSOS-CA), giving us two independent routes.

### 1D. MSSQL impersonation: read the named account and resolve to a stored cred

**File:** `ares-cli/src/orchestrator/automation/mssql_exploitation.rs` (or
wherever `mssql_impersonation` is handled; explorer found no dedicated
automation).

- Add `auto_mssql_impersonation`: for every `mssql_impersonation` vuln, read
  `details["account_name"]` and `details["domain"]`, look up the cred via
  `state.find_credential(...)`. If found, dispatch the mssql-impersonate tool
  call with `impersonate_user=<account>` + the cred.
- Hook the dispatcher in `ares-cli/src/orchestrator/automation/mod.rs`.

### 1E. MSSQL linked-server pivot (castelblack → braavos)

**File:** `ares-cli/src/orchestrator/automation/mssql_link_pivot.rs`

- Today the precondition requires impersonation success first. Either:
  - (a) Loosen: fire linked-server enum chain in parallel as long as we hold
    any cred on the source MSSQL host, OR
  - (b) Gate properly on 1D — once impersonation succeeds, linked-server pivot
    fires within one tick.
- Pick (b) for safety; impersonation usually grants the EXECUTE AS rights
  needed for openquery hops.

### 1F. Kerberoast hashes get queued for cracking

**Files:**

- `ares-cli/src/orchestrator/automation/credential_access.rs` (kerberoast tool
  output handler).
- `ares-cli/src/orchestrator/automation/crack.rs`

- Explorer found kerberoast output never produces `Hash` records, so
  `auto_crack_dispatch` never sees them.
- Change: in the kerberoast result handler, extract each `$krb5tgs$23$...`
  line, parse SPN/username, and push a `Hash { hash_type: "kerberoast",
  username, domain, hash_value, cracked_password: None, ... }`.
- This single change picks up `sql_svc@north`, `sql_svc@essos`, `jon.snow`,
  `sansa.stark` and submits them to hashcat.

### 1G. Credential resolver: NetBIOS↔FQDN equivalence

**Re-scoped after Phase 0 step 3.** Domain compare at L703 is already
case-insensitive; the cross-realm fallback (`any_user` bucket at L711-715)
already fires on non-empty-domain misses for non-Administrator/Guest/krbtgt
users. The only remaining gap is short-form vs FQDN equivalence.

**File:** `ares-cli/src/worker/credential_resolver.rs::find_credential`
(L679-715).

- Reuse `resolve_domain(domain, netbios_map)` from
  `ares-cli/src/orchestrator/recovery/normalize.rs:9` — do not duplicate.
- Normalize the caller's `domain` argument from NetBIOS label to FQDN before
  the compare at L703. Done at the call site so `find_credential` itself
  doesn't gain a new parameter (preserves the existing signature). Caller is
  `resolve_principal_credentials` at L346 — thread the `netbios_map` in there.
- Unit tests after `find_credential_realm_strict_returns_exact_match`
  (L1372): caller passing `"NORTH"` resolves to a credential stored as
  `"north.sevenkingdoms.local"`; reverse direction; behavior unchanged when
  netbios_map is empty.

Phase 0 step 3 found the existing `any_user` fallback already handles the
common case for `jeor.mormont` lookups where vuln details carry the parent
FQDN but credential is stored under a child FQDN (or vice versa). The
NetBIOS-form gap is narrower than originally believed — but still needed for
ingestion paths that propagate raw NetBIOS labels.

**Dependencies inside Phase 1:** 1B can land alongside 1A. 1C is independent of
1A (different domain). 1D needs 1G to be reliable. 1E follows 1D. 1F is
independent. Land 1G first — small surgical change, unblocks 1D, 1E, and helps
everything else.

---

## Phase 2 — Loot/state-tracking fixes (issues #5-#12)

These are display + ingestion bugs. None block execution, but several mask the
fact that we have DA-equivalent material, which leads operators to misallocate
attention.

### 2.5. Secretsdump backfills the users table

**File:** `ares-cli/src/orchestrator/state/publishing/credentials.rs::publish_hash`
and the trusted-sources allowlist in `ares-core/src/reports/dedup.rs`.

- After publishing a hash, derive a `User { username, domain }` and call
  `publish_user(..., source="secretsdump_implicit")`.
- Add `secretsdump_implicit` to `TRUSTED_USER_SOURCES`.
- Skip machine accounts (`$` suffix) — they're trust-key material, surfaced via
  `is_trust_key` in 2.9, not user-table rows.

### 2.6. Rename / regroup credentials and hashes in the report

**File:** `ares-core/templates/redteam/reports/comprehensive_report.md.tera`
(verify path).

- Rename "Credentials" → "Cracked Plaintext".
- Rename "Hashes" → "Hash Material (Pass-the-Hash usable)".
- Add a one-line note at the top of the auth-material section saying NTLM
  hashes are equally usable for authentication.
- Optionally: combined headline count "Auth Material: N entries (X plaintext, Y
  hash)".

### 2.7. Domain prefix dedup (short-form vs FQDN)

**Files:**

- `ares-tools/src/parsers/` — secretsdump parser that emits `Hash` records.
- `ares-core/src/reports/dedup.rs::dedup_hashes`.

- Build a `canonicalize_domain(domain, known_fqdns)` helper that maps NetBIOS
  labels ("north") to FQDNs ("north.sevenkingdoms.local") using FQDNs already
  in state.
- Normalize at write time (parser) so the canonical form is what hits storage.
  Also canonicalize in `dedup_hashes` so legacy short-form rows collapse with
  FQDN ones.
- Share the helper with 1G's resolver.

### 2.8. `source_host` field on local-SAM hashes

**Seam decided in Phase 0 step 5.** If secretsdump's stdout does not name the
source host (likely — the tool is invoked as `secretsdump.py user@HOST` and the
host is implicit), the parser cannot recover it. Thread the value from the
**dispatcher context** instead.

**Files (assuming dispatcher-context threading):**

- `ares-core/src/models/core.rs` — add `Hash.source_host: Option<String>`.
- Wherever the secretsdump tool call is dispatched (likely
  `ares-cli/src/orchestrator/tool_dispatcher/local.rs` or the worker side of
  `ares-cli/src/worker/`) — capture the target hostname/IP from the tool
  invocation and pass it to the result-publishing path.
- Publisher (`ares-cli/src/orchestrator/state/publishing/credentials.rs`) —
  stamp `source_host` on each parsed `Hash` for SAM-section rows.
- `dedup.rs::dedup_hashes` — include `source_host` in the dedup key so the four
  different `ssm-user` hashes don't collapse into one row.
- Report renderer — show `source_host` next to bare local-account names
  (`Administrator (from castelblack.north.sevenkingdoms.local)`).

If Phase 0 step 5 finds secretsdump _does_ emit the host in stdout, fall back
to parser-side extraction instead — but verify before writing code.

### 2.9. Trust-key category and symmetric pairing

**Files:**

- `Hash` struct: add `is_trust_key: bool` and `trust_pair_label: Option<String>`.
- Parser: any username ending in `$` whose owner domain ≠ the machine's home
  domain → `is_trust_key = true`. Set `trust_pair_label` to the NetBIOS label.
- Report template: hoist a "Trust Keys / Forging Material" subsection above the
  generic hash dump.
- Detect symmetric pairs: when two `is_trust_key` hashes share the same
  `hash_value` but flipped `(username, domain)`, render as one row with a
  "symmetric pair" badge.

### 2.10. Current vs previous trust key

Covered in 1B. Surface the `is_previous` flag in the report (and prefer current
at all use sites).

### 2.11. Vulnerabilities table truncation

**Files:** `ares-core/src/reports/vuln_details.rs` (or equivalent) and the
report template.

- Truncate each detail string to a fixed cap (80–120 chars) with an ellipsis.
- Don't truncate the count — confirm rendered list length matches the header.
  If "25 vulns" but only 22 show, something is hard-trimming the iterator;
  trace `details_list` construction for an early `take()` / `limit`.
- Consider one-vuln-per-row layout with details below instead of jamming into a
  single cell.

### 2.12. Host → credentials mapping on shares

**Files:**

- `ares-core/src/models/core.rs::Share` — add `authenticated_as: Option<String>`
  (format `"DOMAIN\\username"`).
- Wherever share enumeration writes results (likely
  `ares-tools/src/parsers/smb.rs` + a publisher in `state/publishing/`),
  capture the credential used and store it.
- Template: add an "Auth" column to the shares table.
- A host-access-matrix view (`host × credential → protocols`) is a tempting
  follow-up but out of scope for this PR — track separately after PR 5 lands.

**Dependencies inside Phase 2:** 2.8 (adding `source_host`) and 2.9
(`is_trust_key`, `trust_pair_label`) both touch the `Hash` struct — land them
in one commit to avoid two migrations. 2.10 piggybacks on 2.9.

---

## Phase 3 — Validation

After each phase, run end-to-end against dreadgoad on whichever infra is
active.

**K8s (red:multi):**

```bash
task -y red:multi:sync:align && task -y red:multi TARGET=dreadgoad
task red:multi:list LATEST=true
task red:multi:loot LATEST=true
task red:multi:report LATEST=true
```

**EC2 (ec2:*):** the loot/report commands work the same; deploy is different.
Sync code to the EC2 instance via the usual deploy path, kick off an operation,
then:

```bash
task -y ec2:loot LATEST=true
task -y ec2:report LATEST=true
```

Either path validates against the same lab; pick whichever matches the
operator's current setup.

**Unit tests** (must accompany the code PRs, not deferred to integration):

- PR 0: `find_credential` case-insensitive domain match;
  short-form↔FQDN equivalence (e.g. `north` vs `north.sevenkingdoms.local`);
  trust-credential fallback when same-domain miss with non-empty domain;
  `canonicalize_domain` helper.
- PR 1: trust-key FQDN resolution — positive case (corroborating signal present
  → candidate accepted) and **negative case** (no corroborating signal →
  candidate rejected, no dispatch). The negative case is the regression guard
  against blind guessing.
- PR 3: `auto_mssql_impersonation` builds the right tool call given an
  `mssql_impersonation` vuln + matching credential in state.
- PR 4: kerberoast result handler emits a `Hash` record per `$krb5tgs$23$...`
  line with correct `username` / `domain`.

**Pass conditions:**

- **Phase 1:**
  - `forest_trust_escalation 10.1.2.58 essos` flips to ✓ within one operation.
  - At least one `essos.local\*` hash appears in the dump (proves the
    secretsdump end of the forge+secretsdump chain landed, not just the
    ticketer end).
  - `essos.local` shows up in the domains-compromised count (`2/3` → `3/3`
    or `essos.local: DA`).
  - ESC1 against ESSOS-CA fires.
  - `mssql_impersonation 10.1.2.51` is exploited with `jeor.mormont`.
  - `sql_svc` Kerberoast hashes appear in the cracking queue.
- **Phase 2:** User count includes secretsdump-derived accounts. Hash table has
  a "Trust Keys" section at the top. ESSOS$ rows are tagged current/previous.
  Short-form vs FQDN duplicate gone. Local-SAM hashes show `source_host`.
  Shares table shows which cred established access. Vuln list shows all 25
  entries without `--output truncated--`.

---

## Commit / PR strategy

- **PR 0 — Phase 1G alone** ("relaxed credential resolver"): tiny prerequisite
  that lets reviewers see the credential-resolver behavior change in isolation,
  decoupled from the trust-automation diff. Unblocks 1D/1E too.
- **PR 1 — Phase 1A/1B** ("close inter-realm trust escalation"): trust-key
  NetBIOS-label fallback + current/previous disambiguation. Riskiest change in
  the plan; keeping it on its own makes the diff reviewable.
- **PR 2 — Phase 1C**: ADCS low-priv authenticator.
- **PR 3 — Phase 1D/1E**: MSSQL impersonation automation + linked-server pivot
  gating.
- **PR 4 — Phase 1F**: Kerberoast → hash queue.
- **PR 5 — Phase 2 (loot/report)**: bundle the schema changes (`Hash`, `Share`
  fields) and renderer changes. Single PR is easier to review than five tiny
  ones.

Branch names:

- `feat/credential-resolver-relaxed-domain`
- `feat/trust-essos-kill-path`
- `feat/adcs-lowpriv-auth`
- `feat/mssql-impersonation-auto`
- `feat/kerberoast-crack-queue`
- `feat/loot-report-clarity`

---

## Pushback / risks

- **Issue #6 (merge or rename Credentials/Hashes):** rename, don't merge. The
  structural distinction (plaintext vs hash) matters at the tool-dispatch layer
  — many tools accept one but not the other. Renaming the section headings is
  enough to remove operator confusion.
- **Issue #8 (multiple Administrators):** before adding `source_host`,
  double-check secretsdump output actually includes the source host name — if
  the tool dispatch wraps the call with a hostname argument, that's the
  cleanest place to thread it through. Don't add a field if upstream tooling
  already loses the info.
- **Phase 1A trust-key FQDN resolution:** the riskiest change in the plan. A
  bad NetBIOS-to-FQDN guess would send the orchestrator to forge tickets for
  the wrong realm. The 1A design forbids any blind guess: the candidate FQDN
  must be present in state and corroborated by at least one independent record
  (host, credential, or vuln). The PR 1 negative-case unit test (above) is the
  regression guard. If the design ever drifts back toward inferring a domain
  from a label alone, that test must fail.
