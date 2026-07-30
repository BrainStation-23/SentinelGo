# SentinelOps EPM — Frontend & Database Update Plan (Agent v2 Alignment)

## How to use this document

This document is written to be handed directly to an AI coding assistant (or a
human engineer) working **inside the SentinelOps repository** — the
Frontend + Database + RBAC + RPC "management plane" — to bring it up to
parity with capabilities the **SentinelGo endpoint agent** has already shipped.
Treat every section below as an instruction, not just a report: where it says
"required," build that; where it says "reuse," do not re-architect the
existing table/RPC/component it names.

**Ground rules for whoever executes this plan (carry these into every phase):**

1. **Do not redesign the existing EPM architecture.** `epm_policies` /
   `epm_policy_rules` / `epm_elevation_requests` / the five existing RPCs /
   the existing RBAC permissions all keep working exactly as they do today.
   Everything below is **additive**.
2. **Reuse before you build.** The Software Catalog integration
   (`list_software_catalog_rule_sources`), the approval workflow tables, the
   RBAC permission model, the existing wizard/dialog/table components, and the
   device compliance/posture engine (`src/lib/posture.ts` per
   `docs/epm_feasibility_assessment_Forntend.md`) already exist and should be
   extended, not duplicated.
3. **Verify before you trust.** This document was produced from the
   **SentinelGo agent repository**, which does not contain the SentinelOps
   frontend or database source. Every statement below about "current Frontend
   status" or "current Database status" is transcribed from three documents
   that live in *this* repo — `docs/epm_implementation_report.md`,
   `docs/EPM Capability.md`, and `docs/epm_feasibility_assessment_Forntend.md`
   — which the user has confirmed are the primary source of truth for the
   SentinelOps side. They are a point-in-time snapshot. **Before implementing
   any item below, re-verify its "current status" claim against the actual,
   current SentinelOps source** (grep the real schema, the real RPC list, the
   real route tree) — do not implement a fix for a gap that has since closed,
   and do not skip a gap that this snapshot missed.
4. **Everything about the agent side of this document is current and
   verified** — it was compiled by reading the SentinelGo agent's own source
   (`internal/epm/*.go`, `internal/store/schema_epm_v3.go`,
   `internal/config/config.go`) and its authoritative docs
   (`docs/EPM-Operator-Guide.md`, `docs/EPM-RPC-Contract-v2.md`,
   `.kiro/specs/epm/tasks.md`) as of 2026-07-29, not from a stale assessment.
   Where the agent's own docs are stale, this document says so explicitly
   (see `docs/EPM-Capability-Assessment.md`'s own addendum, which flags itself
   as historical).

---

## 1. Executive Summary

### Current EPM implementation status

- **SentinelOps Frontend (v1 feature set): ~95% complete.** Full policy
  authoring UI (wizard, rule editor, templates), self-service elevation
  requests, single-tier approval workflow, searchable audit log viewer, and a
  fleet-wide analytics dashboard — all built against a **flat rule model**
  (hash / publisher / path / script-hash / wildcard, single device-or-group
  target, single `expires_at`, allow/deny only).
- **SentinelOps Database (v1 feature set): ~100% complete.** `epm_policies`,
  `epm_policy_rules`, `epm_elevation_requests`, the `epm_elevation_logs` view,
  eleven RPCs, RLS, and RBAC permissions are all shipped and, per
  `docs/epm_implementation_report.md`, production-ready.
- **SentinelGo Agent: v1 fully implemented and wired end-to-end; v2 fully
  implemented but not yet reachable in production.** The agent's v1 policy
  engine (the exact flat-rule model the Frontend/DB already author) is live,
  tested on real Windows/Linux/macOS hardware, and consumes the *exact* wire
  format the current `epm-policy-sync` task payload already sends — no
  Frontend/DB work is required to keep v1 working. Layered on top, the agent
  has since shipped a **v2 condition-tree policy engine** (34 condition
  kinds, 7 verdicts, 6 elevation modes, launch constraints, signed/versioned
  bundles with staged activation and rollback, device-context and
  network-location conditions, process monitoring with child-process
  containment, and a richer audit schema) — none of which the current
  Frontend or Database can author, deliver, or display.

### Overall integration readiness

The two sides are **not misaligned so much as at different generations**. The
v1 slice is a complete, matched pair (Frontend ✅ / DB ✅ / Agent ✅). The v2
slice is agent-complete but management-plane-absent (Frontend ❌ / DB ❌ /
Agent ✅), **with one important caveat**: the agent's own delivery path for
v2 policy (`internal/epm/transportbe` + `BundleManager`) is built and tested
but **not wired into the agent's running `main_integration.go`** — the agent
today only ever reads flat v1 rules off the existing `epm-policy-sync` task
payload. This means:

- Building the v2 **backend RPC contract** (`docs/EPM-RPC-Contract-v2.md`) is
  safe, additive, and matches an already-frozen agent-side spec — do it now.
- But **no traffic will reach it** until a separate, out-of-scope change lands
  in the SentinelGo agent repo (wiring `transportbe`/`BundleManager` into
  `main_integration.go`). Every Phase below that depends on v2 delivery is
  marked **"blocked on agent wiring"** so this plan's executor does not
  mistake "backend built" for "feature live."

### High-level gaps between the current UI/DB and the new agent capabilities

| Area | Gap |
|---|---|
| Policy expressiveness | No condition trees (AND/OR/NOT over 34 kinds) — only single hash/publisher/path/wildcard per rule |
| Verdicts | Only allow/deny — agent supports 7 verdicts (`audit_only`, `monitor`, `prompt`, `require_justification`, `require_approval` in addition) |
| Elevation lifetime | Only a single `expires_at` — agent supports 6 elevation modes including true run-once, session-bound, and break-glass |
| Launch safety | No child-process containment, token-type, runtime-limit, or interactive-session-required controls exposed |
| Context-awareness | No business-hours, network-location, or device-posture conditions on a rule, despite posture data existing elsewhere in the platform |
| Policy integrity | No versioning, no signing, no staged rollout, no rollback UI — agent supports all of this via signed bundles |
| Telemetry depth | Audit log shows ~9 v1 fields; agent can produce ~26 fields including process tree and matched-condition explainability |
| Process containment visibility | Zero visibility into child-process monitoring/kill events the agent can now generate |
| Audit retention | Backend retains EPM events 7 days (shared `audit_logs` table); agent itself retains 30 days locally — a real, pre-existing compliance gap unrelated to v2 |

---

## 2. Feature Gap Analysis

### Summary table

| # | Feature | Agent | Frontend | Database | Required Update | Priority |
|---|---|---|---|---|---|---|
| 1 | Flat rule matching (hash/publisher/path/wildcard) | ✅ | ✅ | ✅ | None — baseline, keep as-is | — |
| 2 | Script/installer hash + `allowed_args` | ✅ | ✅ | ✅ | None | — |
| 3 | Service-scoped elevation (`allowed_service_name`) | ✅ | ✅ | ✅ | None | — |
| 4 | JIT expiry (single `expires_at`) | ✅ | ✅ | ✅ | None | — |
| 5 | Self-service request + single-tier approval | ✅ | ✅ | ✅ | Minor (see #22) | Low |
| 6 | Condition-tree rules (34 kinds, AND/OR/NOT, specificity) | ✅ | ❌ | ❌ | Both | **Critical** |
| 7 | New verdicts (`audit_only`/`monitor`/`prompt`/`require_justification`/`require_approval` on direct match) | ✅ | ❌ | ❌ | Both | **Critical** |
| 8 | Elevation modes + Grants (run-once/temporary/session/time-based/emergency) | ✅ | 🟡 approximated | ❌ | Both | High |
| 9 | Launch constraints (token type, child-process policy, max runtime, working dir, require-interactive) | ✅ | ❌ | ❌ | Both | High |
| 10 | Device posture conditions (disk encryption, secure boot, firewall, AV, compliance, domain/Entra join, TPM) | ✅ (Unknown until wired) | ❌ | 🟡 posture data exists, not linked to EPM | Both | High |
| 11 | Network-location conditions (network type, VPN, corporate network) | ✅ (Unknown until wired) | ❌ | ❌ | Both | High |
| 12 | Time conditions (business hours, day-of-week, per-rule timezone) | ✅ | ❌ | ❌ | Both | High |
| 13 | Rule groups (shared conditions/defaults across rules) | ✅ | ❌ | ❌ | Both | Medium |
| 14 | Signed, versioned policy bundles (generation, ed25519, canaries, staged activation) | ✅ | ❌ | ❌ | Both | **Critical** (needs key-custody design) |
| 15 | Bundle rollback (manual generation-based `epm-policy-rollback` task + automatic crash-loop) | ✅ | ❌ | 🟡 trivial task-enqueue wrapper | Both | Medium (coupled to #14) |
| 16 | Backend transport v2 RPCs (`agent_epm_get_policy` etc.) | 🟡 client complete, not wired into agent runtime | ❌ | ❌ | DB/API only | High, but **inert until agent wiring lands** |
| 17 | Process monitoring & child-process containment telemetry | ✅ | ❌ | ❌ | Both | High |
| 18 | Richer audit schema (verdict/mode/bundle/specificity/command line/process tree/justification/approval/grant/device context/matched conditions/agent version) | ✅ | 🟡 v1 fields only | 🟡 view exists, new columns unexposed | Both | High |
| 19 | Live interactive prompt exchange (Prompt/RequireJustification dialogs actually shown) | 🔴 built, not driven live (always falls back to deny) | N/A | N/A | **None — agent-side only** | Future agent work |
| 20 | Software inventory `sha256_hash`/`publisher` fields for rule authoring | ✅ | 🟡 verify exposure | 🟡 verify exposure | Verification only | Low |
| 21 | EPM audit retention (backend 7 days vs. agent-local 30 days) | N/A | N/A | 🔴 existing gap | DB only | High, **zero agent dependency** |
| 22 | Multi-tier approval chains | N/A (approval is entirely backend-side already) | ❌ | ❌ | Both | Medium, **zero agent dependency** |
| 23 | Installer templates for DMG/RPM | N/A (generic path+hash mechanism already covers it) | ❌ (no wizard preset) | N/A | Frontend only | Low |
| 24 | Reporting gaps (top allowed apps, approval trends, security events, risky apps, compliance reports, SIEM/webhook) | N/A | ❌ | 🟡 needs new views/RPCs | Both | Medium |

### Detailed gap analysis, grouped by theme

#### 2.1 Condition-tree rules (v2 policy model) — Feature #6

- **Agent status:** Fully implemented (`internal/epm/condition.go`,
  `compile.go`, `engine_v2.go`, `matchers*.go`). A rule's match logic is a
  tree of AND/OR/NOT nodes over ~34 `ConditionKind` values (application
  identity, invocation, principal, directory/org, device posture, network,
  time, platform). Matching is **specificity-ranked**, not tier-ranked like
  v1: a rule combining several strong conditions can outrank a bare hash
  match, but a rule's *strongest single identity condition* still sets a hard
  ceiling — a publisher-only v2 rule can never outrank a hash rule, exactly
  preserving v1's precedence semantics. Unknown/stale context data fails
  closed for allow-family verdicts and fails safe (denial stands) for
  deny-family verdicts.
- **Frontend status:** None. `EPMRuleEditor` only edits the five v1 fields.
- **Database status:** None. `epm_policy_rules` has no columns for a
  condition tree; no enum/reference table for the 34 condition kinds exists.
- **Gap:** A full new authoring surface and a new JSONB-backed rule
  representation are both needed. v1 rules are not deprecated and must
  continue to work unmodified.
- **Required Frontend changes:** New "Advanced Rule" mode in the rule editor;
  a visual condition-tree builder (see §6); a reference-data-driven condition
  picker (kind, valid operators per kind, platform applicability).
- **Required Database changes:** `epm_rules_v2`, `epm_rule_groups`, a
  `epm_condition_kinds` reference/lookup table for the UI, JSONB columns for
  `conditions`/`outcome`, and depth/node-count validation mirroring the
  agent's own `MaxConditionDepth=32`/`MaxConditionNodes=512` caps.
- **Dependencies:** None for authoring/storage. **Delivery to a live agent
  requires the v2 RPC contract (Feature #16), which is itself blocked on
  agent-side wiring.**

#### 2.2 New verdicts and elevation modes — Features #7, #8

- **Agent status:** `Verdict` (allow/deny/audit_only/monitor/prompt/
  require_justification/require_approval) and `ElevationMode`
  (silent/run_once/temporary/session/time_based/emergency) are both fully
  implemented, including `epm_grants` bookkeeping for consumable/time-bound
  grants (`uses_count`/`max_uses`/`session_id`/`revoked`).
- **Frontend/DB status:** The current system only knows allow/deny, and
  approximates "run once" with a short time window and "elevate only during
  business hours" not at all (per `EPM Capability.md`).
- **Gap:** No schema concept for a verdict beyond allow/deny, no grant
  lifecycle visibility, and no admin-facing way to revoke an active grant
  early.
- **Required changes:** New `verdict`/`elevation_mode` enums, an
  `epm_grants` mirror table for fleet-wide visibility (populated via audit
  events referencing `grant_id`, since grants are created and tracked
  agent-side), and a new "Active Grants" page (§3).
- **Important limitation to flag to stakeholders, not hide:** there is
  **no mechanism today for the backend to push an early grant revocation to
  a specific already-issued grant** — the closest agent-side lever is
  pushing an updated policy (v1 full-replace) or a bundle rollback
  (v2, generation-level). True per-grant remote revocation would be a new
  agent capability; scope the "Revoke" button's backend action accordingly
  (documented limitation, not a silent gap) or treat it as a **future
  Endpoint Agent enhancement**.

#### 2.3 Launch constraints — Feature #9

- **Agent status:** `Constraints{TokenType, ChildProcess, ChildAllowed,
  MaxRuntime, WorkingDir, RequireInteractiveSession}` fully implemented as
  part of a v2 rule's `Outcome`.
- **Gap:** Zero UI or schema for any of these. `ChildProcess` in particular
  is the platform's answer to the "child-process escalation" risk flagged in
  `docs/epm_feasibility_assessment_Forntend.md` §Security and the "Not
  Present" child-process-containment line in `docs/EPM Capability.md` §18 —
  **this risk has already been closed on the agent side** and only needs a
  management-plane surface now.
- **Required changes:** Constraints sub-form on the Advanced Rule Editor;
  new columns/JSONB sub-object on `epm_rules_v2.outcome`.

#### 2.4 Device posture and network-location conditions — Features #10, #11

- **Agent status:** `CondDiskEncryption`, `CondSecureBoot`, `CondFirewall`,
  `CondAntivirus`, `CondCompliance`, `CondDomainJoined`, `CondEntraJoined`,
  `CondNetworkType`, `CondVPNActive`, `CondCorporateNetwork` all exist as
  condition kinds. **They resolve to Unknown until a `ContextProvider` is
  wired** (`epm_context_mode`) — which is the agent's honest, safe default,
  not a bug. Corporate-network definitions (CIDRs, DNS suffixes, gateway
  MACs, VPN adapter patterns) are meant to be delivered as part of a policy
  bundle's `Defaults`.
- **Frontend/DB status:** Per `docs/EPM Capability.md` §"Device Context
  Conditions," the platform **already has a device compliance/posture
  engine** (`src/lib/posture.ts`) tracking Firewall, Antivirus/Defender,
  Secure Boot, Core Isolation, USB storage, BitLocker/recovery-key status —
  but it is completely disconnected from EPM policy evaluation.
  Business-hours and network-location conditions do not exist anywhere in
  the schema.
- **Gap:** This is a **wiring gap, not a data gap**, for posture. Reuse the
  existing posture engine's data model rather than inventing a parallel one.
  Business-hours/corporate-network definitions are genuinely new (tenant-wide
  settings), matching `PolicyBundle.Defaults` on the agent side.
- **Required Frontend changes:** A new EPM Settings section for tenant-wide
  Business Hours and Corporate Network definitions (§3.12); condition-tree
  picker entries for posture/network kinds, each annotated in the UI with
  "requires device context collection to be enabled" so admins understand
  why a rule might silently not match on devices where it isn't.
- **Required Database changes:** `epm_tenant_context_defaults` table (business
  hours, corporate CIDRs/DNS suffixes/gateway MACs/VPN adapter patterns,
  org/department); a foreign-key or lookup bridge from EPM condition
  authoring to the existing posture tables (no new posture storage).

#### 2.5 Signed, versioned policy bundles — Features #14, #15

- **Agent status:** `PolicyBundle` (schema_version, bundle_id, generation —
  monotonic per tenant, parent_id for deltas, mode full/delta, issued_at,
  not_after, rules, rule_groups, defaults) fully implemented, with optional
  ed25519 signing (`epm_policy_signature_mode`: off/warn/require), staged
  compile-and-canary validation before activation, and **two rollback
  paths**: an operator-pushed `epm-policy-rollback` task (`{"generation": N}`
  — native handler already registered and shipped) and automatic
  crash-loop protection (3 restarts in 10 minutes reverts automatically).
- **Frontend/DB status:** None. No concept of a policy "version" exists —
  `docs/epm_implementation_report.md` §11 explicitly lists "Rule Versioning:
  🔴 Not Implemented" as a known limitation, and §6.5 of
  `docs/EPM-Operator-Guide.md` corroborates it end to end.
- **Gap:** This is the single highest-value, highest-complexity item in this
  plan. It also introduces a genuinely new *category* of backend concern:
  **cryptographic key custody** for bundle signing, which has no precedent
  elsewhere in the current schema and needs its own design review (Supabase
  Vault / KMS-backed key storage, who may request a signature, key rotation).
- **Required Frontend changes:** Bundle version history view with diff
  between generations; a "publish" action distinct from "save draft"; a
  policy simulator that runs the bundle's own canary checks before publish
  (mirrors what the agent already does — huge trust-building UX win, see
  §6); a one-click rollback-to-generation action, gated by a **separate**
  permission from ordinary policy editing.
- **Required Database changes:** `epm_policy_bundles`, `epm_bundle_canaries`,
  signing-key metadata (never the private key itself — that belongs in a
  secrets manager), bundle `state` lifecycle (draft/staged/active/
  rolled_back/superseded/rejected).
- **Dependencies:** Delivery is blocked on agent wiring (§16); rollback is
  further blocked on bundles actually existing on a device to roll back
  *to* — do not ship a rollback button that has nothing to roll back until
  bundle delivery is live end to end.

#### 2.6 Backend transport v2 RPCs — Feature #16

- **Agent status:** `internal/epm/transportbe` implements the full v1/v2
  negotiation client, unit-tested against a mock server. **Not called by the
  running agent** — `main_integration.go`'s `epm-policy-sync`/`epm-audit-sync`
  scheduler tasks still use the v1 task-payload piggyback exclusively. A 404
  or 501 on any v2 RPC is read by the agent as "not implemented here" and
  the agent **latches to v1 for the remainder of the process's run** — which
  is exactly what happens today against the current backend, by design, with
  zero risk of breaking anything by building these RPCs now.
- **Gap:** None of the five RPCs specified in `docs/EPM-RPC-Contract-v2.md`
  exist. Building them is safe and additive; see §5 for exact signatures —
  **implement them to the letter of that contract**, since the agent's own
  code already expects those exact shapes and there is no room to
  renegotiate the wire format from the backend side alone.
- **Required Database/API changes:** All five RPCs, described in full in §5.
- **Dependencies:** **Building this does not make v2 policy live.** A
  corresponding, out-of-scope SentinelGo agent change (wiring
  `transportbe`/`BundleManager` into `main_integration.go`) is required
  before any of these RPCs receive real traffic. Flag this explicitly in
  release notes and do not report v2 as "shipped" to end users until that
  agent change lands and has been validated against a real device.

#### 2.7 Process monitoring & child-process containment telemetry — Feature #17

- **Agent status:** `internal/epm/procmon` (Windows Event ID 4688/4689,
  Linux netlink proc connector with polling fallback, macOS gopsutil
  polling) plus `internal/epm/enforce` (terminate-on-violation, kill-rate
  limiter, never-kill list). Gated by `epm_process_monitor_mode`
  (off/observe/enforce). **This is observation-and-containment, not
  prevention** — the agent's own docs are explicit that nothing here blocks
  a process before it runs; measured containment latency ranges from ~1ms
  (Linux netlink) to ~3s (Windows polling fallback).
- **Frontend/DB status:** None. This is an entirely new telemetry stream.
- **Gap:** No table, no RPC, no UI page exists for process-start/exit events
  or containment (kill) actions.
- **Required Frontend changes:** A new Process Timeline view (fleet-wide
  report and a per-device tab), explicitly labeled with the
  observe-then-kill/latency caveat above so operators do not overestimate
  what this buys them.
- **Required Database changes:** `epm_process_events` table (high-volume;
  design its retention policy deliberately shorter than the general audit
  trail — see §4).

#### 2.8 Richer audit schema — Feature #18

- **Agent status:** `epm_audit_log` (agent-local) gained 17 new columns in
  schema v5: `verdict`, `mode`, `bundle_id`, `rule_version`, `specificity`,
  `publisher`, `command_line`, `process_id`, `parent_pid`, `parent_path`,
  `exit_code`, `justification`, `approval_id`, `grant_id`, `device_context`,
  `matched_conditions`, `agent_version`, `retain_until`. `matched_conditions`
  in particular is a direct explainability win: it lists exactly which
  condition kinds fired in the winning rule, and `Decision.Indeterminate`
  (surfaced via the same audit path) explains *why* something was denied due
  to unverifiable context.
- **Frontend/DB status:** `docs/EPM Capability.md` §19 confirms only ~9
  fields are captured today (user, device, hostname, app path, app hash,
  policy/rule, allow/deny, script hash, service name, timestamp); explicitly
  not captured: IP address, exit code, process tree, parent/child processes,
  publisher-on-the-log-row.
- **Gap:** Both the ingestion path (what the backend accepts/stores) and the
  display path (what the Elevation Logs table renders) need to grow.
- **Required Database changes:** Either extend the existing
  `audit_logs`-backed `epm_elevation_logs` view's underlying JSONB payload
  contract, or — recommended — introduce a dedicated, typed
  `epm_elevation_events` table for query performance and retention control,
  while **preserving the existing view's column contract** for anything
  already consuming it (see §8, Backward Compatibility).
- **Required Frontend changes:** Extend `EPMElevationLogTable` and
  `ExplainDenialDialog` with the new columns; a "why" panel that renders
  `matched_conditions`/`Indeterminate` in plain language.

#### 2.9 Non-agent-gated fixes (buildable immediately, independent of any agent change)

These three items require **zero SentinelGo changes** and should be
prioritized as quick, high-confidence wins:

- **#21 Audit retention mismatch (backend 7 days vs. agent-local 30 days).**
  A pure backend/DB fix: either give `EPM_ELEVATION_LOG` rows their own
  retention policy distinct from the general `audit_logs` table, or complete
  the migration to a dedicated `epm_elevation_events` table (§2.8) with its
  own, longer retention. This is flagged in `docs/EPM Capability.md` twice
  ("Audit every privileged action 🟡 ... retention is currently only 7 days"
  and again under §19) as a standing limitation, not something introduced by
  this plan.
- **#22 Multi-tier approval chains.** The existing approval flow
  (`approve_epm_elevation_request`/`deny_epm_elevation_request`) is entirely
  backend/frontend logic — the agent has no role in *deciding* an approval,
  only in eventually receiving the resulting rule. A configurable
  escalation chain (Help Desk → Security Team, N-of-M approvers) is a pure
  DB/RBAC/Frontend feature.
- **#23 DMG/RPM installer wizard templates.** The generic path+hash+args
  mechanism already covers these installer types on the agent side (same as
  MSI/EXE/PKG/DEB today) — only a Guided Template preset is missing from the
  wizard. Zero backend or agent work.

---

## 3. Frontend Changes Required

Conventions used below: **[NEW]** marks a page/component that does not exist
today; everything else extends an existing page named in
`docs/epm_implementation_report.md` §2.

### 3.1 EPM Dashboard (`_app.epm.index.tsx`)

- **Existing functionality:** fleet-wide analytics, rule breakdowns by tier,
  recent activity, elevations-over-time chart.
- **Required changes:**
  - Verdict breakdown widget expanded from allow/deny to all 7 verdicts.
  - "Active Grants" summary card (count by mode: run-once outstanding,
    temporary active, session-bound active).
  - "Policy Generation" card per device/fleet once bundles are live (v1
    devices show "classic," v2 devices show their active `generation`).
  - Process-containment summary card (violations observed vs. enforced-kill
    count in the last 24h) — only rendered once `epm_process_monitor_mode`
    telemetry starts arriving, hidden otherwise (no empty-state noise).
  - Agent transport-mode adoption chart (% of fleet on v1 vs. v2 transport)
    once v2 RPCs are live — a rollout-tracking tool, not a permanent fixture.
- **New actions:** none (dashboard remains read-only).
- **Permission gating:** unchanged (`epm_policies:view`).

### 3.2 Policy List

- **Existing functionality:** `EPMPolicyTable` — paginated/filterable list of
  policies via `list_epm_policies`.
- **Required changes:** a "Type" column/badge distinguishing **Classic**
  (v1 flat rule) from **Advanced** (v2 bundle-backed) policies; for Advanced
  policies, a generation number and signature-status badge
  (unsigned/warn/verified/failed) and a state badge
  (draft/staged/active/rolled_back).
- **New filters:** filter by type (Classic/Advanced), by signature status,
  by state.
- **New navigation:** Advanced policies route to a new Bundle Detail view
  (§3.9) instead of the classic `$policyId.tsx` editor.

### 3.3 Policy Details / Policy Editor (`_app.epm.$policyId.tsx`)

- **Existing functionality:** target scope (device vs. group) + embedded
  rule editor, for Classic policies.
- **Required changes:** unchanged for Classic policies (preserve exactly —
  this is the backward-compatibility anchor). Add a visible, non-default
  "Convert to Advanced" action that creates a new v2 bundle seeded from the
  existing v1 rules via the agent's own `UpgradeV1` semantics (one-way, with
  a confirmation dialog explaining v1 keeps working unless this policy is
  explicitly deployed as a bundle).

### 3.4 Policy / Bundle Wizard

- **Existing functionality:** `CreateEPMPolicyWizardDialog` — Name → Scope →
  Select Applications → Rules, for Classic policies.
- **Required changes:** add a mode toggle at step 1, "Classic rule" (today's
  flow, unchanged) vs. "Advanced rule" (new flow below). Do not merge the
  two flows into one form — v1's simplicity is a feature for the 95% of
  cases that don't need condition trees.
- **New wizard steps (Advanced mode only):**
  1. **Condition Builder** — visual AND/OR/NOT tree editor over the 34
     condition kinds, each rendered from server-supplied metadata (label,
     description, valid operators, platform applicability, "requires device
     context" annotation) — see §5's `list_epm_condition_kinds` RPC and §6.
  2. **Outcome & Verdict** — verdict picker (Allow/Deny/Audit
     Only/Monitor/Prompt/Require Justification/Require Approval) with
     contextual sub-fields: elevation mode + grant window; constraints
     (token type, child-process policy + allowed globs, max runtime, working
     directory, require-interactive-session); message and
     justification-min-length for Prompt/RequireJustification; approval TTL
     and fallback verdict for RequireApproval.
  3. **Rule Groups** — optionally attach the rule to a shared group carrying
     common conditions/defaults.
  4. **Test & Publish** — the policy simulator (§6): author canary
     request/expected-verdict pairs, run them against the compiled rule set
     server-side, and only allow "Publish" once canaries pass — mirroring
     the agent's own pre-activation self-check exactly.
- **New validation:** condition-tree depth/node-count caps mirrored from the
  agent (`MaxConditionDepth=32`, `MaxConditionNodes=512`); a rule with
  `ScriptHash`/script conditions must also carry a path/interpreter
  condition, matching the agent's `PolicyRule` invariant.
- **Required API changes:** see §5.

### 3.5 Application Selection

- **Existing functionality:** calls `list_software_catalog_rule_sources`,
  converts software-catalog entries into `DraftRule` objects.
- **Required changes:** confirm (per §2.4 item #20) that `sha256_hash` and
  `publisher` from the agent's enriched software inventory are surfaced in
  this flow — the Operator Guide explicitly documents these as the
  recommended source for hash/publisher rule authoring. Add (disabled,
  tooltipped "not yet collected by the agent") placeholders for
  `file_name`/`product_name`/`msi_product_code`/`bundle_id`/`package_name`
  condition kinds so the UI is forward-compatible without pretending they
  work today (§2.4 in the Feature Gap table classifies these as agent-gated,
  not actionable now).

### 3.6 Elevation Rules / Rule Editor

- **Existing functionality:** `EPMRuleEditor`/`EPMRuleDraftsTable` — Hash,
  Path, Publisher, Script, Wildcard.
- **Required changes:** in Advanced mode, replace the flat field set with
  the Condition Builder (§3.4) and add the Constraints sub-form. Add a
  per-rule version indicator once backed by `epm_rules_v2.version`.
- **New components:** `EPMConditionTreeEditor`, `EPMConstraintsPanel`,
  `EPMVerdictPicker`.

### 3.7 Rule Management — Rule Groups **[NEW]**

- **New page:** manage `RuleGroup` records (name, shared conditions,
  shared defaults, priority, enabled) independent of any single rule, so
  multiple rules can share a "corporate laptops only" or "IT admins only"
  precondition without repeating it per rule.

### 3.8 Assignments / Device Targeting

- **Existing functionality:** a policy targets exactly one `device_group_id`
  or one `device_id` (mutually exclusive).
- **Required changes:** unchanged for Classic policies. For Advanced
  (bundle-backed) policies, targeting is expressed through
  `PolicyBundle.Defaults.DeviceGroups[]`/`Org`/`Department` — a genuine
  multi-group/org/department targeting capability that does not exist for
  Classic policies today. Do not retrofit this onto `epm_policies` — keep it
  scoped to the bundle model to avoid touching v1's proven mutual-exclusion
  invariant.

### 3.9 Bundles & Versioning **[NEW]**

- **New page:** `_app.epm.bundles.$bundleId.tsx` (or similar) — version
  history for an Advanced policy: list of generations, signature status per
  generation, diff between two generations (rules added/removed/changed),
  "Publish new generation," "Rollback to generation N" (calls the RPC in
  §5 that enqueues the existing `epm-policy-rollback` task — no new agent
  work needed for this specific action, since the native handler already
  ships).

### 3.10 Active Grants **[NEW]**

- **New page or Device Detail tab:** list of active
  run-once/temporary/session grants by device/user, with issued/expires/
  uses-count/max-uses. "Revoke" action exists but must be labeled with the
  real limitation from §2.2 (no guaranteed immediate remote revocation
  today) rather than implying instant effect.

### 3.11 Process Timeline **[NEW]**

- **New page or Device Detail tab:** process start/exit events and
  containment (kill) actions from `epm_process_events`, filterable by
  violation/device/user, with a persistent banner explaining the
  observe-then-kill latency model (§2.7) so this is never mistaken for
  real-time prevention.

### 3.12 Audit History / Elevation Logs

- **Existing functionality:** `EPMElevationLogTable`, searchable/filterable.
- **Required changes:** new columns (verdict badge — 7 states, not 2 — mode,
  bundle+generation link, specificity score, command line, process tree,
  exit code, justification, approval_id, grant_id, agent_version); a "why"
  explain panel rendering `matched_conditions`/`Indeterminate`; new filters
  (by verdict, by bundle generation, by "has violation").
- **`ExplainDenialDialog` changes:** when prefiling a new policy rule from a
  denied v2 event, prefill a condition tree (not just a flat rule) using
  the denial's `Indeterminate`/`Matched` data as a starting point.

### 3.13 Approval Workflow

- **Existing functionality:** `EPMElevationRequestApproveSheet` — single
  reviewer, dual-control (no self-approval).
- **Required changes:** support direct-policy-match `require_approval`/
  `require_justification` verdicts, not just self-service requests — the
  queue must show request **origin** (self-service vs. policy-triggered),
  the matched `rule_id`/`bundle_id`, and an `approval_ttl` countdown.
  Multi-tier approval chains (§2.9 #22) as a later enhancement, gated behind
  its own DB design (see §4) — do not block this section's core work on it.

### 3.14 Activity Timeline

- Treat as the fleet-wide feed feeding the Dashboard (§3.1); extend with the
  same new event types (grant issued/consumed, bundle published/rolled back,
  containment kill) rather than building a separate timeline component.

### 3.15 Reports

- **Existing:** Most Denied Applications, Top Users by Elevation Requests,
  Policy/Rule Usage, Failed Elevation Attempts, Rules Expiring Soon.
- **Required additions** (per `docs/EPM Capability.md` §20 gaps): Most
  Elevated (allowed) Applications, Approval Trends, Security Events, Risky
  Applications, Compliance Reports. SIEM/webhook alerting is a larger,
  separate integration — scope it as its own initiative, not a report page
  (see Roadmap §9, Phase 9).

### 3.16 Settings **[NEW EPM section]**

- **New page/section**, since none exists today per the current route list:
  - Signature mode (off/warn/require) and signing-key metadata display
    (key_id, last rotated — never the private key).
  - Backend transport status (read-only: which transport devices have
    negotiated, once v2 RPCs exist).
  - Grouped log upload / retention configuration (surfacing the fix for
    Feature #21).
  - Tenant Context Defaults: business hours, corporate network CIDRs/DNS
    suffixes/gateway MACs, VPN adapter patterns, org/department — the
    natural home for §2.4's tenant-wide condition inputs, since these are
    account-wide settings, not per-policy fields.

### 3.17 Permission gating updates (cross-cutting)

Every Advanced-mode surface above must be gated behind **new, more
privileged permissions**, distinct from the existing `epm_policies:*` set —
condition-tree authoring, and especially bundle publishing/signing, is more
powerful and more capable of silent misconfiguration than a flat rule. See
§4's RLS section for the exact permission list.

---

## 4. Database Changes Required

All items are **additive**. No existing table, column, RPC signature, or RLS
policy is modified in a breaking way; where an existing RPC gains new
*optional* parameters, defaults preserve today's exact behavior.

### 4.1 New tables

| Table | Purpose | Depends on / feeds |
|---|---|---|
| `epm_policy_bundles` | Signed, versioned policy container — generation, parent_id, mode (full/delta), schema_version, issued_at, not_after, key_id, signature, sig_status, state (draft/staged/active/rolled_back/superseded/rejected) | Bundles & Versioning page (§3.9) |
| `epm_rules_v2` | Condition-tree rule: bundle_id FK, id, group_id FK (nullable), version, enabled, priority, `conditions` JSONB, `outcome` JSONB, effective_from, expires_at, on_unknown, labels, static_spec | Advanced Rule Editor (§3.6) |
| `epm_rule_groups` | Shared conditions/defaults applied to a set of rules: bundle_id FK, id, name, enabled, priority, `conditions` JSONB, `defaults` JSONB | Rule Groups page (§3.7) |
| `epm_bundle_canaries` | Bundle self-check pairs: bundle_id FK, name, request JSONB, context JSONB, expected verdict | Policy simulator (§6) |
| `epm_condition_kinds` | Reference/lookup table: kind, label, description, valid operators, platform applicability, "requires context provider" flag, whether the underlying collector exists yet (drives the disabled/tooltip states in §3.5) | Condition Builder (§3.4, §6) |
| `epm_tenant_context_defaults` | Tenant-wide: business_hours_start/end, business_days, timezone, corporate CIDRs/DNS suffixes/gateway MACs, VPN adapter patterns, org, department, default_verdict | Settings page (§3.16) |
| `epm_grants` | Fleet-wide mirror of agent-local grant lifecycle: grant_id, rule_id, bundle_id, user_id, device_id, mode, uses_count, max_uses, issued_at, expires_at, session_id, revoked, revoked_by, revoked_at | Active Grants page (§3.10) |
| `epm_process_events` | Process start/exit + containment telemetry from procmon/enforce: device_id, observed_at, kind, pid, parent_pid, session_id, user_id, image_path, command_line, exit_code, elevated (tri-state), source, grant_id | Process Timeline page (§3.11) |
| `epm_elevation_events` (recommended) | Typed, first-class replacement/superset of the current `audit_logs`-backed view for EPM events — see §4.4 | Audit History (§3.12) |
| `epm_approval_chains` / `epm_approval_steps` (Phase 8, optional) | Multi-tier approval configuration and per-step resolution | Approval Workflow enhancement (§2.9 #22) |

### 4.2 New columns on existing tables

- `epm_policies`: add a nullable `bundle_id` (FK to `epm_policy_bundles`) and
  a `policy_type` enum (`'classic' | 'advanced'`, default `'classic'`) so
  the Policy List (§3.2) can distinguish and route correctly without a
  separate parallel table for "which policies are v2."
- `epm_elevation_requests`: add `origin` enum (`'self_service' |
  'policy_direct'`), `rule_id`, `bundle_id`, `approval_ttl` — supports §3.13's
  direct-match approval queue without a new table.

### 4.3 New enums

- `epm_verdict`: `allow | deny | audit_only | monitor | prompt | require_justification | require_approval`
- `epm_elevation_mode`: `silent | run_once | temporary | session | time_based | emergency`
- `epm_token_type`: `elevated | system | filtered | user`
- `epm_child_process_policy`: `inherit | observe | allowlist | deny`
- `epm_bundle_state`: `draft | staged | active | rolled_back | superseded | rejected`
- `epm_sig_status`: `unverified | warn | verified | failed`
- (Reuse, do not recreate) existing `approval_status`-equivalent for
  `epm_approvals`-style resolution — check the existing
  `epm_elevation_requests.status` enum first per the "verify before you
  trust" rule in this document's preamble.

### 4.4 Views

- Keep `epm_elevation_logs` exactly as-is for backward compatibility (§8).
- Add a new view (e.g. `epm_elevation_events_v2`) over the recommended
  `epm_elevation_events` table that projects the same column names/shapes
  the *existing* view exposes, plus the new v5-schema columns — so existing
  consumers can migrate at their own pace by switching which view they
  query, rather than being forced to migrate in lockstep with this project.

### 4.5 Indexes

- `epm_rules_v2(bundle_id, enabled)`, `epm_policy_bundles(state)`,
  `epm_policy_bundles(generation)` — mirroring the agent's own local SQLite
  indexes in `internal/store/schema_epm_v3.go` exactly, since query patterns
  (fetch active bundle, fetch enabled rules for a bundle) are the same on
  both sides.
- `epm_grants(rule_id, user_id)`, `epm_grants(expires_at)`.
- `epm_process_events(device_id, observed_at)`, and a partial index on
  violations (`elevated = 'killed'` or similar) for the containment report.
- `epm_elevation_events(device_id, occurred_at)`, `epm_elevation_events(verdict)`,
  `epm_elevation_events(bundle_id)`.

### 4.6 New RPCs

See §5 for full signatures. Summary list:

- **Agent-facing (must match `docs/EPM-RPC-Contract-v2.md` exactly):**
  `agent_epm_get_policy`, `agent_epm_ack_policy`, `agent_epm_enqueue_events`,
  `agent_epm_submit_approval`, `agent_epm_poll_approvals`.
- **Admin/Frontend-facing (new):** `upsert_epm_rule_v2`,
  `upsert_epm_rule_group`, `upsert_epm_tenant_context_defaults`,
  `list_epm_condition_kinds`, `simulate_epm_bundle` (canary dry-run),
  `publish_epm_bundle`, `rollback_epm_bundle`, `list_epm_bundles`,
  `get_epm_bundle`, `list_epm_grants`, `revoke_epm_grant`,
  `list_epm_process_events`.

### 4.7 Existing RPC modifications

- `list_epm_elevation_logs`: add optional parameters (`p_verdict`,
  `p_bundle_id`, `p_has_violation`, `p_mode`) with defaults that reproduce
  today's exact result set when omitted — a pure additive signature change,
  PostgREST-safe.
- `list_epm_policies`: add an optional `p_policy_type` filter; response gains
  `bundle_id`/`policy_type` fields, which existing callers that don't read
  them can safely ignore.
- `upsert_epm_policy` / `upsert_epm_policy_rules` / `push_epm_policy_to_devices`
  / `request_epm_elevation` / `approve_epm_elevation_request` /
  `deny_epm_elevation_request`: **unmodified.** These remain the exclusive
  path for Classic policies and self-service requests.

### 4.8 RLS policy updates

New permissions (additive to the existing `epm_policies:view/manage/deploy`
and `epm_elevation_requests:request/review`):

| Permission | Gates |
|---|---|
| `epm_bundles:manage` | Draft/edit v2 rules, rule groups, tenant context defaults |
| `epm_bundles:publish` | Sign and activate a bundle — **kept separate from `manage`** so authoring and publishing can be different people/roles, matching a release-engineering propose/approve split |
| `epm_bundles:rollback` | Roll back to a prior generation |
| `epm_grants:view` / `epm_grants:revoke` | Active Grants page |
| `epm_process_events:view` | Process Timeline — command-line data can be sensitive; treat as a distinct, narrower grant than general audit viewing |
| `epm_context_defaults:manage` | Tenant Context Defaults settings |

`epm_rules_v2`/`epm_policy_bundles` follow the existing pattern: locked down
by RLS, accessible only through `SECURITY DEFINER` RPCs that check
`public.has_permission()`, exactly like `epm_policy_rules` today.

### 4.9 Audit logging enhancements

- Fix the retention mismatch (§2.9 #21): give EPM events a retention window
  that does not silently undercut the agent's own 30-day local buffer or any
  compliance requirement — 7 days is very likely too short once
  `epm_elevation_events` becomes the record of privileged actions this
  system is designed to prove happened correctly.
- `matched_conditions`/`device_context` should be stored as JSONB (mirroring
  the agent's own shapes) rather than flattened, so the "why" explain panel
  (§3.12) can render them without a lossy round-trip.

---

## 5. API & RPC Changes

### 5.1 New agent-facing RPCs — implement to the letter of `docs/EPM-RPC-Contract-v2.md`

These five signatures come directly from the agent's own frozen contract
(`internal/epm/transportbe/v2_rpc.go`). Do not deviate — the agent-side caller
is already written against this exact shape.

**1. `agent_epm_get_policy`**
```json
// Request
{ "p_cursor_generation": 41 }
// Response — 200, something pending
{ "bundle": { "payload": "<PolicyBundle JSON>", "alg": "ed25519", "key_id": "prod-2026-01", "sig": "<base64>" } }
// Response — 200, nothing newer
{ "bundle": null }
```
`p_cursor_generation` is the last generation the calling device applied; `0`
means "send the latest full bundle for this device's group/tenant."

**2. `agent_epm_ack_policy`**
```json
{ "p_bundle_id": "b-2026-01-29-0007", "p_applied": true, "p_note": "activated at generation 42" }
```
Empty 200 response. `p_applied: false` carries a human-readable rejection
reason in `p_note` (signature failure, canary failure, compile failure).

**3. `agent_epm_enqueue_events`**
```json
// audit rows
{ "p_audit_rows": [ { "ID": 101, "Entry": { "...": "epm.AuditEntry shape" } } ] }
// OR process events (exactly one of the two populated per call)
{ "p_process_events": [ { "ObservedAtUnix": 1774950000, "EventData": "<pre-marshalled procmon.ProcessEvent JSON>" } ] }
```
Empty 200 response. Retried by the agent on 5xx/network failure (10 attempts,
1s→5min backoff); a non-401 4xx is treated as a permanent rejection and the
batch is dropped, not retried forever — **do not return a 4xx for a
transient/soft-fail condition**, since the agent will not retry it.

**4. `agent_epm_submit_approval`**
```json
{ "p_request_id": "6f2b...-uuid", "p_rule_id": "rule-42", "p_user_id": "alice@corp.example.com", "p_app_path": "C:\\Tools\\admin-console.exe", "p_justification": "Deploying hotfix per INC-1234" }
// Response
{ "approval_id": "appr-9f21" }
```

**5. `agent_epm_poll_approvals`**
```json
{ "p_approval_ids": ["appr-9f21", "appr-a044"] }
// Response
{ "approvals": [ { "approval_id": "appr-9f21", "status": "approved", "note": "" }, { "approval_id": "appr-a044", "status": "pending", "note": "" } ] }
```
`status`: `pending | approved | denied | expired`. This is deliberately
two-phase (submit, then poll) rather than a long-held connection — design
`agent_epm_poll_approvals` to be cheap to call frequently.

**Contract behaviors the backend must honor exactly:**
- A 404 or 501 on any of these five must mean "not implemented" — the agent
  reads that as a permanent signal to fall back to v1 for the rest of its
  run. **Do not partially implement one of the five** without the other four
  also existing (even as stubs returning empty results) — a mixed
  implemented/404 state is not a scenario the agent's negotiation logic was
  designed against.
- Headers/auth are identical to every existing agent RPC
  (`Content-Type`, `apikey`, `Authorization: Bearer <JWT>`); a 401 gets one
  agent-side retry after token refresh — no special handling needed.

### 5.2 New admin/frontend RPCs

| RPC | Purpose | Notes |
|---|---|---|
| `list_epm_condition_kinds` | Returns condition-kind metadata for the Condition Builder | Read-only reference data; safe to cache client-side |
| `upsert_epm_rule_v2` | Create/update a v2 rule (condition tree + outcome) inside a draft bundle | Mirrors `upsert_epm_policy_rules`'s full-replace-within-bundle pattern where practical |
| `upsert_epm_rule_group` | Create/update a rule group | |
| `upsert_epm_tenant_context_defaults` | Business hours / corporate network / org / department | Tenant-scoped, singleton-per-tenant like the existing "Self-Service Elevation Grants" singleton policy pattern |
| `simulate_epm_bundle` | Dry-run: compile a draft bundle and run its canaries server-side, returning pass/fail per canary and the compiled rule count | The policy simulator (§6) — server-side mirror of the agent's own `BundleManager.Apply` pre-activation check |
| `publish_epm_bundle` | Assign the next `generation`, optionally sign (per `epm_policy_signature_mode`), transition draft→staged/active | Gated by `epm_bundles:publish` |
| `rollback_epm_bundle` | Enqueue an `epm-policy-rollback` task (`{"generation": N}`) for target devices — reuses the agent's already-shipped native handler | Gated by `epm_bundles:rollback` |
| `list_epm_bundles` / `get_epm_bundle` | Version history / single-bundle detail | |
| `list_epm_grants` / `revoke_epm_grant` | Active Grants page | See §2.2's revocation-latency caveat |
| `list_epm_process_events` | Process Timeline page | |

### 5.3 Payload/response and validation requirements

- Condition trees submitted via `upsert_epm_rule_v2` must be validated
  server-side against the same structural caps the agent enforces
  (`MaxConditionDepth=32`, `MaxConditionNodes=512`, `MaxRulesPerBundle=20000`)
  — reject oversized/pathological trees at authoring time, not at agent
  compile time.
- `Outcome.FallbackVerdict` must default to `deny` when omitted, exactly
  matching `Outcome.EffectiveFallback()` agent-side — never let the backend
  silently default an interaction verdict's fallback to `allow`.
- Reject (or clearly warn on) a rule with `ScriptHash`/script conditions set
  without an accompanying path/interpreter condition — mirrors the agent's
  own documented invariant in `internal/epm/policy.go`.

### 5.4 Error handling improvements

- `agent_epm_enqueue_events`: distinguish retryable (5xx) from permanent
  (4xx-other-than-401) failures precisely, since the agent's retry behavior
  branches on this.
- `publish_epm_bundle`: a bundle that fails its own canaries must be
  rejected with a structured, canary-by-canary failure reason surfaced back
  to the Frontend — do not return a generic "publish failed."

---

## 6. UI/UX Improvements

Recommendations aligned with enterprise EPM products (BeyondTrust, CyberArk
EPM, Delinea), scoped to what this platform's architecture already supports
well:

- **Policy simulator / canary tester.** The single highest-leverage UX
  addition: let an admin write "if a user on a corporate-network,
  BitLocker-enabled device tries to run `X` during business hours, expect
  `allow`" test cases and run them against a draft bundle before publishing.
  This is not a new concept to invent — it is a direct UI wrapper around a
  mechanism the agent already implements and trusts (`Canary`,
  `BundleManager.Apply`'s pre-activation self-check).
- **Visual condition-tree builder**, not a raw JSON editor — nested
  AND/OR/NOT groups with drag-to-reorder, each leaf rendered from
  `epm_condition_kinds` metadata (kind label, operator dropdown scoped to
  valid operators for that kind, a value input whose shape matches the
  operator — e.g. a time-range picker for `between` on `business_hours`).
- **Explainable audit rows.** Surface `matched_conditions` and
  `Indeterminate` as a plain-language sentence ("Denied because
  `corporate_network` could not be verified"), not just raw condition-kind
  strings — this is the single biggest driver of admin trust in a
  default-deny system.
- **Bundle diff view.** Side-by-side generation N vs. N-1: rules
  added/removed/changed, defaults changed — standard "policy version
  history" pattern from enterprise EPM products, and directly requested in
  `docs/epm_implementation_report.md` §11/§13 as a known gap.
- **Verdict-aware badges.** Extend `EPMDecisionBadge` from a 2-state to a
  7-state badge set with distinct colors/icons per verdict family (allow
  family vs. deny family vs. interaction family), so a filtered/sorted
  Elevation Logs table remains scannable.
- **Grant utilization view.** A small, focused widget (not a full
  dashboard) showing run-once/temporary/session grant consumption — answers
  "is this JIT elevation actually being used" at a glance.
- **Search/filtering improvements.** Elevation Logs and Process Timeline
  should share a consistent filter bar pattern (device, user, verdict/kind,
  date range, "has violation") rather than diverging per page.
- **Approval SLA visibility.** Show `approval_ttl` as a live countdown in
  the Approval queue for `require_approval`-verdict requests, so reviewers
  see time pressure the same way the agent-side requester experiences it.
- **Reports.** Add the concretely-missing dashboards from
  `docs/EPM Capability.md` §20 (Most Elevated Applications, Approval Trends,
  Security Events, Risky Applications, Compliance Reports) using the same
  chart components already used for the existing five reports — no new
  charting library needed.

---

## 7. Integration Mapping

### 7.1 Condition-tree policy authoring and evaluation

```
internal/epm/condition.go + compile.go + engine_v2.go   (Agent — DONE)
        ↓ (device pulls via) agent_epm_get_policy         (New RPC — Phase 2)
epm_policy_bundles + epm_rules_v2 + epm_rule_groups        (New DB — Phase 1)
        ↓ authored via
upsert_epm_rule_v2 / upsert_epm_rule_group / simulate_epm_bundle / publish_epm_bundle  (New RPCs — Phase 2/3)
        ↓ surfaced in
Advanced Rule Editor + Condition Builder + Policy Simulator  (New Frontend — Phase 3)
        ↓
Administrator authors a conditional elevation policy, tests it against canaries, publishes a signed bundle
```
**Status: blocked end-to-end on SentinelGo wiring `transportbe`/`BundleManager` into `main_integration.go` (out of this plan's scope).**

### 7.2 Process monitoring and child-process containment

```
internal/epm/procmon + internal/epm/enforce                (Agent — DONE)
        ↓ (uploads via) agent_epm_enqueue_events(p_process_events)
epm_process_events                                          (New DB — Phase 6)
        ↓ surfaced via
list_epm_process_events                                     (New RPC — Phase 6)
        ↓
Process Timeline page / Device Detail tab                   (New Frontend — Phase 6)
        ↓
Administrator investigates child-process violations and tunes ChildProcess constraints
```
**Status: also blocked on agent wiring (§7.1), since `agent_epm_enqueue_events` is v2-transport-only.**

### 7.3 Signed bundles, staged activation, and rollback

```
internal/epm/bundle.go + bundle_manager.go + bundle_verify.go + probation.go  (Agent — DONE)
        ↓
agent_epm_get_policy / agent_epm_ack_policy                 (New RPC — Phase 2)
        ↓
epm_policy_bundles (state machine) + signing-key metadata    (New DB — Phase 4)
        ↓
Bundle version history / diff / publish / rollback UI         (New Frontend — Phase 4)
        ↓
Administrator rolls back a bad policy push (or observes an automatic crash-loop rollback in the audit trail)
```
**Rollback specifically also has a currently-reachable half:** the
`epm-policy-rollback` native task handler already ships in the agent and
works against **any** bundle a device already has locally — so
`rollback_epm_bundle`'s task-enqueue side can be built and tested now, ahead
of the rest of this chain, using synthetic/test bundle IDs if needed.

### 7.4 New verdicts and direct-match interactive approval

```
internal/epm/verdict.go (Prompt/RequireJustification/RequireApproval)  (Agent — DONE, evaluation only)
internal/epm/prompt/*   (native dialogs)                                (Agent — DONE, NOT driven live)
        ↓
agent_epm_submit_approval / agent_epm_poll_approvals                    (New RPC — Phase 2)
        ↓
epm_elevation_requests.origin='policy_direct' + rule_id/bundle_id        (New DB column — Phase 1)
        ↓
Extended Approval Workflow queue (origin badge, TTL countdown)           (New Frontend — Phase 8)
        ↓
Reviewer approves/denies a policy-triggered (not just self-service) elevation request
```
**Status: the evaluation and RPC-submission halves can be built now; the
actual live prompt shown to the end user is explicitly NOT implemented
agent-side yet (§2, Feature #19) — every interaction verdict falls back to
`deny` until that separate agent work lands. Do not present this as a
working end-user flow until it does.**

### 7.5 Richer audit and explainability

```
epmSchemaV5 (17 new epm_audit_log columns, agent-local)                 (Agent — DONE)
        ↓ uploaded via
agent_epm_enqueue_events(p_audit_rows)  OR  enriched v1 log upload       (New/extended RPC — Phase 2/7)
        ↓
epm_elevation_events (new typed table)                                   (New DB — Phase 7)
        ↓
Extended Elevation Logs table + "why" explain panel                      (New Frontend — Phase 7)
        ↓
Administrator performs root-cause analysis on an unexpected allow/deny
```

---

## 8. Backward Compatibility

**Guiding principle carried through every phase below: v1 keeps working,
byte-identical, forever, regardless of how much v2 gets built.** This is not
just a design goal — it is what the agent's own documentation guarantees
(`docs/EPM-Operator-Guide.md` §6: *"the v1 rule format ... is not deprecated,
and existing `epm-policy-sync` payloads continue to apply with byte-identical
results"*), and the management plane should make the same promise.

- **Existing tables untouched.** `epm_policies`, `epm_policy_rules`,
  `epm_elevation_requests` keep their exact current schema; new columns
  added to them (§4.2) are nullable/defaulted and ignorable by any consumer
  that doesn't know about them.
- **Existing RPCs untouched or additive-only.** No existing RPC's required
  parameters, return shape, or default behavior changes (§4.7). New optional
  parameters default to reproducing today's exact output.
- **Existing view preserved.** `epm_elevation_logs` keeps its current column
  contract; a new view/table serves the richer v2 data (§4.4) so existing
  dashboards/integrations built on the current view do not break.
- **Existing components reused, not replaced.** `EPMRuleEditor`,
  `EPMPolicyTable`, `EPMElevationLogTable`, `CreateEPMPolicyWizardDialog`,
  `EPMElevationRequestApproveSheet` all keep their current (Classic-mode)
  behavior as the default; Advanced-mode functionality is additive UI
  reached through explicit mode toggles, not a replacement of the default
  path.
- **No forced migration.** A policy authored today in Classic mode never
  needs to become an Advanced bundle. "Convert to Advanced" (§3.3) is
  opt-in, one-way, and explicit.

### Potential breaking changes and mitigations

| Risk | Mitigation |
|---|---|
| A future backend change accidentally routes v1-shaped `epm-policy-sync` payloads through new v2-only code paths | Keep the v1 task-payload piggyback and any new v2 RPC path as fully independent code paths on the backend, exactly mirroring the agent's own `transportbe` negotiation split — never conditionally rewrite a v1 payload through v2 logic |
| `epm_policies.policy_type`/`bundle_id` columns get treated as required by some future code path, breaking existing Classic-only rows | Default `policy_type='classic'`, `bundle_id=NULL`; any query reading these must treat NULL/classic as the (permanent) common case, not an edge case |
| Retention-policy change (§4.9) deletes data some existing integration depends on being short-lived | Extending retention is safe (more data retained, not less); if retention is ever *shortened* for a different reason, treat that as its own change with its own review — not bundled into this plan |
| A new, more privileged permission (§4.8) accidentally narrows access for existing `epm_policies:manage` holders | New permissions are additive grants, never a replacement for existing ones; an existing Classic-policy admin's access must be unaffected by this project shipping |

---

## 9. Implementation Roadmap

Phases are ordered so that **every phase before Phase 2 is independently
useful even if the SentinelGo agent-wiring work never lands**, and every
phase from Phase 2 onward is explicitly marked with its agent dependency so
priority calls can be made with full information.

### Phase 1 — Database Foundation (no agent dependency)
- **Objectives:** Land the additive schema for v2 without touching delivery.
- **Tasks:** Create all new tables (§4.1), new columns (§4.2), enums (§4.3),
  `epm_elevation_events` + compatibility view (§4.4), indexes (§4.5), new
  RLS permissions (§4.8).
- **Dependencies:** None.
- **Expected outcome:** Schema exists and is queryable; nothing in
  production behavior changes yet.
- **Complexity:** Medium (careful RLS/permission design, especially the
  publish/manage split).

### Phase 2 — Backend v2 RPC Contract Implementation
- **Objectives:** Implement the five agent-mandated RPCs to spec.
- **Tasks:** `agent_epm_get_policy`, `agent_epm_ack_policy`,
  `agent_epm_enqueue_events`, `agent_epm_submit_approval`,
  `agent_epm_poll_approvals` — exact shapes from §5.1.
- **Dependencies:** Phase 1.
- **Expected outcome:** Contract complete and testable against a mock
  agent client (the agent repo's own `internal/epm/transportbe` tests are a
  good reference for expected request/response shapes). **No real agent
  traffic until the separate agent-side wiring change lands — flag this
  clearly in any release communication.**
- **Complexity:** Medium.

### Phase 3 — Condition-Tree Policy Authoring
- **Objectives:** Let admins author (not yet publish/deliver) Advanced
  policies.
- **Tasks:** `list_epm_condition_kinds`, `upsert_epm_rule_v2`,
  `upsert_epm_rule_group`; Advanced Rule Editor + Condition Builder UI
  (§3.4, §3.6, §3.7); feature-flag the entire Advanced mode off by default.
- **Dependencies:** Phase 1.
- **Expected outcome:** Full authoring experience, gated behind a flag,
  usable for internal review before any delivery path exists.
- **Complexity:** High (the visual condition-tree builder is the single
  largest UI component in this plan).

### Phase 4 — Bundle Publishing & Signing Infrastructure
- **Objectives:** Version, sign, and stage-activate policy bundles.
- **Tasks:** `simulate_epm_bundle`, `publish_epm_bundle`,
  `rollback_epm_bundle`, `list_epm_bundles`/`get_epm_bundle`; key-custody
  design and implementation (Supabase Vault/KMS); Bundle version
  history/diff/publish/rollback UI (§3.9).
- **Dependencies:** Phases 1–3. Rollback's task-enqueue half is testable
  ahead of full delivery (§7.3).
- **Expected outcome:** A bundle can be authored, simulated, and published
  to a `staged`/`active` state in the database, even before any device can
  fetch it.
- **Complexity:** High (key custody is a new security-sensitive subsystem).

### Phase 5 — Device Context & Network/Time Conditions
- **Objectives:** Wire posture/network/time conditions into the condition
  picker and tenant settings.
- **Tasks:** `epm_tenant_context_defaults` table + `upsert_epm_
  tenant_context_defaults` RPC; bridge condition authoring to the existing
  posture engine's data (reuse, do not duplicate — §2.4); Settings page
  section (§3.16).
- **Dependencies:** Phase 3.
- **Expected outcome:** Business-hours/corporate-network/device-posture
  conditions are authorable and correctly annotated with their
  data-availability caveats.
- **Complexity:** Medium.

### Phase 6 — Process Monitoring & Containment Visibility
- **Objectives:** Surface procmon/enforce telemetry.
- **Tasks:** `epm_process_events` table, `list_epm_process_events` RPC,
  Process Timeline UI (§3.11).
- **Dependencies:** Phase 2 (events arrive via `agent_epm_enqueue_events`) —
  **blocked on agent wiring for live data**, but the table/RPC/UI can be
  built and tested with synthetic data first.
- **Complexity:** Medium.

### Phase 7 — Audit & Reporting Overhaul
- **Objectives:** Close the audit-depth and retention gaps.
- **Tasks:** `epm_elevation_events` table + compatibility view (if not
  already done in Phase 1); retention-policy fix (§2.9 #21, §4.9); extended
  `EPMElevationLogTable`/`ExplainDenialDialog` (§3.12); new reports (§3.15).
- **Dependencies:** Phase 1 for schema; retention fix and new report pages
  have **no agent dependency** and can ship early/independently if
  prioritized ahead of the rest of this phase.
- **Complexity:** Medium.

### Phase 8 — Approval Workflow Enhancements
- **Objectives:** Support direct-policy-match interaction verdicts in the
  approval queue; optionally add multi-tier chains.
- **Tasks:** `epm_elevation_requests` new columns (§4.2); extended Approval
  queue UI (§3.13); (optional, separately prioritizable) `epm_approval_chains`/
  `epm_approval_steps` for multi-tier approval (§2.9 #22 — **zero agent
  dependency**, can be sequenced independently of everything else in this
  roadmap).
- **Dependencies:** Phase 2 for the direct-match half (blocked on agent
  wiring); none for the multi-tier-chain half.
- **Complexity:** Medium.

### Phase 9 — UI/UX Refinement & Installer Templates
- **Objectives:** Polish and the remaining low-effort gaps.
- **Tasks:** DMG/RPM wizard templates (§2.9 #23); verdict-aware badges,
  bundle diff view, grant utilization widget, approval SLA countdown (§6);
  scope (not necessarily build) SIEM/webhook alerting as its own follow-on
  initiative.
- **Dependencies:** Varies per item; most have none.
- **Complexity:** Low–Medium.

### Phase 10 — Validation & Testing
- **Objectives:** Confirm the whole chain works against a real SentinelGo
  agent once the agent-side wiring change lands.
- **Tasks:** Feature-flagged staged rollout; validate `agent_epm_get_policy`
  negotiation and fallback behavior against a real device; validate
  `simulate_epm_bundle`'s canary results match what the agent itself would
  compute (cross-check against `internal/epm`'s own test suite's expected
  outputs where practical); validate rollback against a real staged bundle.
- **Dependencies:** All prior phases, plus the out-of-scope agent-side
  wiring change.
- **Complexity:** High (this is the phase most likely to surface
  integration surprises, consistent with the agent repo's own repeated
  experience that cross-compilation/unit tests do not catch real-environment
  bugs — see `.kiro/specs/epm/tasks.md`'s Notes section for four concrete
  examples of exactly that pattern on the agent side).

---

## 10. Final Readiness Assessment

*(Percentages below describe readiness against the full v1+v2 agent
capability surface, not against v1 alone — recall from §1 that v1 alone is
~95%/100% complete per the existing report.)*

- **Current Frontend completion (v1+v2 combined):** ~35–40%. Essentially all
  v1 capability is shipped; essentially none of the v2 surface (condition
  trees, new verdicts/modes, constraints, context conditions, bundles,
  process monitoring, extended audit) exists yet.
- **Current Database completion (v1+v2 combined):** ~35–40%. Same pattern —
  v1 schema/RPCs complete; v2 schema/RPCs entirely absent.
- **Agent integration readiness:** v1 is 100% production-wired. v2 is
  **agent-complete but 0% deliverable** until the out-of-scope
  `transportbe`/`BundleManager` wiring lands in the SentinelGo agent — this
  is the single ceiling on how much of this plan can actually go live,
  regardless of how much Frontend/DB work is done.

### Features ready immediately (no new work needed)
- Everything in the v1 feature set (§2, rows 1–5): flat rule matching,
  script/installer elevation, service scoping, JIT expiry, self-service +
  single-tier approval.

### Features requiring Frontend work only
- None identified — every v2 feature that has a UI component also has a
  data-model gap, because nothing in the current schema can represent v2
  concepts yet.
- **Exception:** DMG/RPM installer wizard templates (§2.9 #23) — Frontend
  polish only, no schema change needed.

### Features requiring Database work only
- Audit retention fix (§2.9 #21) — a policy/config change on existing
  infrastructure, not a new Frontend surface (though a Settings toggle to
  expose it is cheap Frontend work worth bundling).

### Features requiring both Frontend and Database work
- Condition-tree rules, new verdicts/elevation modes, launch constraints,
  device-posture/network/time conditions, rule groups, signed bundles,
  process monitoring visibility, richer audit display, multi-tier approval
  chains — i.e., nearly everything in §2's gap table.

### Features requiring future Endpoint Agent enhancements (not actionable by this plan)
- Live interactive prompt exchange (Prompt/RequireJustification/
  RequireApproval dialogs actually shown to the end user) — agent-side
  `Server`↔session-helper wiring, currently always falls back to deny.
- Guaranteed, immediate remote grant revocation (§2.2).
- The v2 RPC delivery path going live at all (`transportbe`/`BundleManager`
  wiring into `main_integration.go`) — the precondition for Phases 2, 4, 6,
  and half of Phase 8 actually mattering in production.
- Software-inventory collectors for `product_name`/`msi_product_code`/
  `bundle_id`/`package_name` (condition kinds already registered agent-side,
  matching Unknown until a collector exists).
- Linux GPG signature verification for publisher-based rules (documented,
  accepted, structural limitation of Linux package managers — not a gap this
  plan or a future agent patch is expected to close).

### Recommended implementation priority

1. **Phase 1 + the retention half of Phase 7** — pure DB work, zero risk,
   closes a real compliance gap today.
2. **Phase 2** — build the contract now while it's cheap, even though it's
   inert until agent wiring lands; this de-risks that future integration
   entirely.
3. **Phase 3 + Phase 5** — deliver the full authoring/simulation experience
   (feature-flagged) so it is validated and ready the moment delivery
   becomes possible.
4. **Phase 8's multi-tier-chain half** — independent, self-contained value,
   sequence opportunistically.
5. **Phases 4, 6, and the rest of 8** — sequence once there is a committed
   date for the agent-side wiring change, since their value is fully gated
   on it.
6. **Phase 9** — ongoing polish, interleave throughout rather than treating
   as a discrete final phase.
7. **Phase 10** — the moment the agent-side wiring change ships.
