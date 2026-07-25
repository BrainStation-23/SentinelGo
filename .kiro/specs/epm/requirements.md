# Requirements — Enterprise Endpoint Privilege Management (EPM)

## Overview

SentinelGo currently runs as a privileged system daemon (SYSTEM on Windows, root on Linux/macOS) whose job is passive monitoring: it collects hardware/software inventory and audit logs, and executes remote tasks pushed from Supabase. EPM adds a new capability on top of this foundation: allowing a standard (non-admin) user to launch a **specific, policy-approved application** with elevated privileges, without granting that user admin rights generally.

This document defines requirements for EPM using the existing agent as the enforcement point. Requirements are grouped by area and written in EARS-like form (`WHEN <trigger>, THE SYSTEM SHALL <behavior>`) so each is independently testable.

Reference: `docs/EPM-Capability-Assessment.md` (per-platform gap analysis this spec is based on).

## Goals

- Let an administrator define rules ("policies") describing which applications a given user may run elevated.
- Let a standard user request elevation for an application from their own session; the agent decides allow/deny based on policy, with no further prompt beyond what the OS's own consent UI requires.
- Record every elevation request (allowed or denied) as an audit event, both locally (offline-durable) and synced to Supabase.
- Do this identically in shape across Windows, Linux, and macOS, even though the underlying privilege-elevation primitive differs per OS.
- Ship disabled by default (`enable_epm: false`) so existing installs are entirely unaffected until an operator opts in.

## Non-Goals

- EPM is not a general sudo/UAC replacement for interactive shells; it targets specific, pre-approved GUI/CLI applications only.
- No policy authoring UI is specified here (frontend feasibility is tracked separately in `docs/epm_feasibility_assessment_Forntend`).
- No cross-machine session sharing or remote-desktop-specific elevation flows in the initial phases.

## Functional Requirements

### FR-1 Configuration

1. WHEN the agent loads configuration, THE SYSTEM SHALL support an `enable_epm` boolean field, defaulting to `false` when absent.
2. WHEN `enable_epm` is `false`, THE SYSTEM SHALL NOT start any EPM component (policy sync, IPC listener, elevation pipeline) — behavior must be bit-for-bit identical to a build without EPM.
3. WHEN the agent loads configuration, THE SYSTEM SHALL support an `epm_policy_sync_interval` duration field, defaulting to 5 minutes when absent or zero.
4. THE SYSTEM SHALL reject no existing config fields and SHALL NOT change the on-disk schema of any field that exists today.

### FR-2 Policy Model

1. THE SYSTEM SHALL represent a policy rule with: target application (by absolute path, glob path pattern, publisher/signer identity, or file hash), the user or group it applies to, an allow/deny decision, an optional expiry timestamp, and a priority.
2. WHEN evaluating a rule set against an elevation request, THE SYSTEM SHALL select the highest-priority matching rule using this precedence, highest first: file-hash match, publisher/signer match, exact path match, glob path match, wildcard match.
3. WHEN no rule matches a request, THE SYSTEM SHALL deny by default.
4. WHEN a matching rule's expiry timestamp is in the past, THE SYSTEM SHALL skip that rule as if it did not exist.
5. THE SYSTEM SHALL evaluate policy identically regardless of host OS — the policy engine itself is platform-agnostic; only how its decision is *enforced* (the actual privilege elevation) is platform-specific.

### FR-3 Policy Distribution

1. THE SYSTEM SHALL receive policy rules through the existing remote task pipeline (a task with a dedicated slug), reusing the durable SQLite task queue, retry, and auth-refresh behavior already implemented for other native tasks.
2. WHEN a policy-sync task is executed, THE SYSTEM SHALL upsert the rules contained in its payload into a local SQLite store and remove previously stored rules that are no longer present in the payload, so the local cache always reflects the latest full rule set delivered.
3. THE SYSTEM SHALL persist policy rules locally so elevation decisions can be made while the agent is offline from Supabase.

### FR-4 Elevation Request Flow (per platform, later phases)

1. WHEN a standard user requests elevation for an application via the platform-specific EPM client, THE SYSTEM SHALL identify the requesting user's session, compute the target binary's SHA-256 hash and (where available) its publisher/signer identity, and evaluate policy before launching anything.
2. WHEN policy allows the request, THE SYSTEM SHALL launch the target process in the requesting user's desktop session with elevated privileges, using the platform-native mechanism (Windows: `CreateProcessAsUser` with a duplicated, privilege-adjusted token; Linux: `fork`+`setresuid`+`execve`; macOS: Authorization Services).
3. WHEN policy denies the request, THE SYSTEM SHALL NOT launch the process and SHALL return a denial reason to the requesting client.
4. Communication between the unprivileged user-space client and the privileged agent SHALL use a local, OS-native IPC channel (Windows: Named Pipe; Linux/macOS: Unix Domain Socket), never a network-exposed port.

### FR-5 Auditing

1. WHEN an elevation is requested, allowed, or denied, THE SYSTEM SHALL record an audit entry containing: request ID, user, application path and hash, decision, matched policy ID (if any), and launch timestamp.
2. THE SYSTEM SHALL persist audit entries locally first (durable, survives agent restart and offline periods) and mark each as synced only after successful upload to Supabase.
3. THE SYSTEM SHALL use a dedicated log category (`EPM_ELEVATION_LOG`) distinct from existing log categories so EPM events can be filtered independently in the backend.

### FR-6 Backward Compatibility

1. Existing tables, config fields, models, and native task handlers SHALL NOT be modified in behavior or schema by this work.
2. All new SQLite tables SHALL live in their own database file/migration set, independent of `software`, `services`, and `tasks` stores.
3. Every new package SHALL compile under `CGO_ENABLED=0` for `linux/amd64`, `darwin/amd64`, `darwin/arm64`, and `windows/amd64` — platform-specific EPM primitives live in `_windows.go`/`_linux.go`/`_darwin.go` files, never behind cgo.

## Non-Functional Requirements

- **Security:** Default-deny policy evaluation; no elevation without an explicit matching allow rule. Audit trail is append-only from the enforcement point's perspective (entries are marked synced, never deleted, until explicitly pruned).
- **Reliability:** Policy sync and audit upload must tolerate Supabase being unreachable; both use local SQLite as the durable buffer, matching the existing task/audit-log store pattern.
- **Portability:** No `import "C"` anywhere in the EPM code path (see CLAUDE.md hard rule) — all OS integration goes through `golang.org/x/sys/windows`, POSIX syscalls via the Go standard library, or subprocesses to OS-provided CLIs.
- **Observability:** Every elevation decision is traceable end-to-end from request to audit record via a shared request ID.

## Acceptance Criteria Summary

| ID | Criterion |
|----|-----------|
| AC-1 | `enable_epm: false` (default) produces zero behavioral change vs. current agent. |
| AC-2 | Policy engine unit tests cover all five priority tiers plus expiry and default-deny. |
| AC-3 | `epm-policy-sync` task upserts and prunes rules idempotently given repeated identical payloads. |
| AC-4 | Every elevation attempt produces exactly one audit row, synced status transitions correctly. |
| AC-5 | `make verify-cross` and `make check-no-cgo` pass with all EPM code present. |
