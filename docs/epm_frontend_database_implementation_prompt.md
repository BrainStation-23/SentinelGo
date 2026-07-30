# Implementation Prompt — SentinelOps EPM Frontend & Database (Agent v2 Alignment)

> **Purpose of this file:** Copy the block below into your Frontend/Database AI IDE
> (Cursor, Windsurf, Claude Code, Copilot Workspace, etc.) when working inside the
> **SentinelOps repository**. It is written to be pasted as-is. Attach
> `docs/epm_frontend_database_update_plan.md` (the full blueprint) alongside it — the
> prompt references that document as the authoritative specification.

---

## THE PROMPT — copy from here

You are a senior full-stack engineer working on **SentinelOps**, an enterprise
device-management platform. Your task is to extend its **Endpoint Privilege
Management (EPM)** module — Frontend (React + TanStack Router + TanStack Query +
Tailwind) and Database (Supabase / PostgreSQL with RLS and `SECURITY DEFINER`
RPCs) — so that the management plane fully supports capabilities the SentinelGo
endpoint agent has already implemented.

### Context you must internalize before writing any code

SentinelOps is the **management plane**: policy authoring UI, PostgreSQL schema,
RBAC, RPCs, approval workflow, audit viewing. The **SentinelGo agent** is the
separate **enforcement plane** that runs on endpoints, evaluates policy locally,
elevates approved processes, and uploads telemetry. The two communicate only
through Supabase RPCs and the agent task queue (`agent_command_tasks`).

The agent has shipped two generations of its policy engine:

- **v1 (live in production today):** flat rules — one of `app_hash` /
  `publisher` / `app_path` / `script_hash` / wildcard per rule, plus `user_id`,
  `decision` (allow|deny), `expires_at`, `priority`, `allowed_args`,
  `allowed_service_name`. This is exactly what the current SentinelOps schema and
  UI already author, and it works end to end. **It must keep working unchanged.**
- **v2 (fully implemented in the agent, but not yet reachable in production):**
  a condition-tree policy engine with ~34 condition kinds, 7 verdicts, 6 elevation
  modes, launch constraints, signed/versioned policy bundles, device-posture and
  network-location conditions, process monitoring with child-process containment,
  and a much richer audit schema. **None of this can currently be authored,
  delivered, or displayed by SentinelOps.** Closing that gap is your job.

**Critical caveat you must respect and communicate, never quietly ignore:** the
agent's own v2 *delivery* path (`internal/epm/transportbe` + `BundleManager`) is
built and unit-tested but **is not yet wired into the agent's running
`main_integration.go`**. Building the v2 backend RPCs is safe and additive (the
agent currently 404s against them and correctly falls back to v1 by design), but
**no real device traffic will reach them until a separate, out-of-scope change
lands in the SentinelGo agent repository.** Do not describe v2 features as "live"
or "shipped" in any UI copy, changelog, or status report until that agent change
is confirmed. Where the plan marks a phase "blocked on agent wiring," treat that
as a hard fact about production readiness, not a soft caveat.

### Authoritative specification

`docs/epm_frontend_database_update_plan.md` is your complete implementation
blueprint. It contains, in order:

1. Executive Summary — current status of Frontend, Database, and Agent
2. Feature Gap Analysis — a 24-row table plus per-theme detail, each row
   classified as Already Implemented / Requires Frontend / Requires Database /
   Requires Both / Requires Future Agent Enhancement
3. Frontend Changes Required — page by page, including new components, dialogs,
   wizards, filters, validation, navigation, and permission gating
4. Database Changes Required — new tables, columns, enums, views, indexes, RPCs,
   RLS policies, and audit enhancements, each with its rationale and the frontend
   feature that depends on it
5. API & RPC Changes — exact signatures, payloads, responses, validation rules,
   and error-handling contracts
6. UI/UX Improvements — enterprise-EPM-aligned recommendations
7. Integration Mapping — Agent → RPC → Database → Frontend → Admin workflow, per
   major feature
8. Backward Compatibility — guarantees, risks, and migration strategies
9. Implementation Roadmap — 10 phases with objectives, tasks, dependencies,
   expected outcomes, and complexity estimates
10. Final Readiness Assessment — completion percentages and prioritization

Read that document in full before starting. Follow its phase ordering unless you
have a concrete, stated reason to deviate.

### Non-negotiable engineering constraints

1. **Preserve the existing architecture. Every change is additive.** Do not
   redesign `epm_policies`, `epm_policy_rules`, `epm_elevation_requests`, the
   `epm_elevation_logs` view, the existing eleven RPCs, or the existing RBAC
   permission model. New capability lives in new tables, new RPCs, and new UI
   surfaces reached through explicit mode toggles.

2. **Backward compatibility is a hard requirement, not a goal.** Existing
   policies, existing rules, and existing agent deployments must continue to work
   byte-identically after your changes. New columns on existing tables must be
   nullable or defaulted. New RPC parameters must be optional, with defaults that
   reproduce today's exact behavior. The existing `epm_elevation_logs` view keeps
   its current column contract; richer v2 data goes in a new table/view so
   existing consumers migrate at their own pace.

3. **Reuse before you build.** The Software Catalog integration
   (`list_software_catalog_rule_sources`), the approval workflow tables, the RBAC
   permission model, the existing wizard/dialog/table components
   (`EPMRuleEditor`, `EPMPolicyTable`, `EPMElevationLogTable`,
   `CreateEPMPolicyWizardDialog`, `EPMElevationRequestApproveSheet`,
   `EPMDecisionBadge`), and the existing device compliance/posture engine
   (`src/lib/posture.ts`) all already exist. Extend them. Do not create parallel
   implementations of things this codebase already does well.

4. **Verify the current state before implementing each item.** The blueprint's
   claims about "current Frontend status" and "current Database status" were
   transcribed from documentation snapshots, not from live source. Before
   implementing any item, grep the actual schema, the actual RPC list, and the
   actual route tree to confirm the gap still exists. Do not build a fix for
   something already fixed; do not skip something the snapshot missed. Report any
   discrepancy you find rather than silently working around it.

5. **Match the agent's contracts exactly where they are already frozen.** The five
   agent-facing RPCs (`agent_epm_get_policy`, `agent_epm_ack_policy`,
   `agent_epm_enqueue_events`, `agent_epm_submit_approval`,
   `agent_epm_poll_approvals`) have request/response shapes the agent's own client
   code is already written against. Implement them to the letter of §5.1 of the
   blueprint. You cannot renegotiate the wire format from the backend side alone.
   Specifically: a 404/501 on any of the five makes the agent permanently latch to
   v1 for the rest of its process run, so do not ship a partial subset; and
   `agent_epm_enqueue_events` must return 5xx for retryable conditions only,
   because the agent permanently drops a batch on any non-401 4xx.

6. **Mirror the agent's validation limits server-side.** Reject condition trees
   exceeding `MaxConditionDepth = 32`, `MaxConditionNodes = 512`, or
   `MaxRulesPerBundle = 20000` at authoring time rather than letting them fail at
   agent compile time. Default `Outcome.FallbackVerdict` to `deny` when omitted —
   an interaction verdict that cannot be carried out must never silently degrade
   to allow.

7. **Security posture.** All new tables follow the existing pattern: locked down
   by RLS, mutated only through `SECURITY DEFINER` RPCs that check
   `public.has_permission()`. Introduce the new permissions listed in §4.8 as
   additive grants that never narrow an existing role's access. Keep
   `epm_bundles:publish` separate from `epm_bundles:manage` so authoring and
   publishing can be different people. Never store a private signing key in the
   database — key custody belongs in Supabase Vault or a KMS and warrants its own
   design review before Phase 4.

8. **Feature-flag the entire Advanced (v2) surface off by default** until the
   end-to-end path is validated against a real device.

### Deliverables, in phase order

Work through the blueprint's ten phases. For each phase, produce:

- **Database:** idempotent, reversible migration files following this project's
  existing migration naming and structure; new RPCs with explicit parameter and
  return types; RLS policies; indexes.
- **Frontend:** new routes/pages/components/dialogs following existing file
  naming and folder conventions; TanStack Query hooks for every new RPC;
  permission gating on every new surface; loading, empty, and error states.
- **Types:** shared TypeScript types matching the database shapes exactly —
  including the verdict, elevation-mode, token-type, child-process-policy,
  bundle-state, and signature-status enums.
- **Tests:** coverage for every new RPC's permission checks and validation rules,
  and for the condition-tree builder's structural constraints.
- **Documentation:** update the relevant docs when a phase changes user-facing
  behavior.

Prioritize in this order, per §10 of the blueprint:

1. Phase 1 (database foundation) plus the audit-retention fix — pure DB work,
   zero agent dependency, closes a real compliance gap that exists today (EPM
   events currently retained 7 days on the backend versus 30 days on the agent).
2. Phase 2 (the five agent-facing v2 RPCs) — cheap to build now, de-risks the
   future agent integration entirely, inert until agent wiring lands.
3. Phases 3 and 5 (condition-tree authoring, device-context/time conditions) —
   feature-flagged, so the authoring experience is validated and ready the moment
   delivery becomes possible.
4. The multi-tier approval-chain work in Phase 8 — fully independent of the
   agent, sequence it opportunistically.
5. Phases 4, 6, and the remainder of Phase 8 — sequence once there is a committed
   date for the agent-side wiring change.

### Working method

- Before each phase, state which blueprint sections you are implementing and
  confirm the current-state assumptions you verified.
- Implement one phase at a time. Do not begin a phase whose dependencies are not
  satisfied.
- After each phase, summarize what changed, what is now testable, and what
  remains blocked (and on what).
- Flag any place where the blueprint conflicts with what you find in the actual
  codebase, rather than silently choosing one.
- If a requirement cannot be met without breaking backward compatibility, stop
  and surface the tradeoff instead of proceeding.

Begin with Phase 1. Confirm your understanding of the scope and your verification
of the current schema state before writing any migration.

## THE PROMPT — copy to here
