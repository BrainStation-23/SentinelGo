# EPM Backend RPC Contract v2

**Status: agent-side plumbing complete, no backend implementation exists yet.**
This document specifies five new Supabase RPC functions the SentinelGo agent
is prepared to call (`internal/epm/transportbe/v2_rpc.go`), and is the
deliverable for whoever implements the backend side. `main_integration.go`
now builds a `transportbe.Negotiator` and consults it once per
`epm-policy-sync` cycle, so `agent_epm_get_policy` (via `Probe`) is genuinely
called against the configured Supabase project today — but only as a
negotiation probe. No RPC response is acted on: `epm-policy-sync` still
fetches and applies rules exclusively through the existing v1 task-payload
piggyback, because a v2-fetched `PolicyBundle` has nowhere to go yet
(`BundleManager` is not wired into `epm.Server`'s rule source). Until both a
real backend and that engine wiring exist, `epm_backend_transport` should
stay at its default (`auto`), which negotiates and — since v2 does not exist
— always falls back to v1 after the first probe.

## Conventions

- Every RPC is a Postgres function called the same way the agent already
  calls `agent_get_tasks`/`agent_update_task`: `POST
  {SUPABASE_URL}/rest/v1/rpc/<function_name>`.
- Every request carries the same three headers the agent already sends on
  every RPC call:
  - `Content-Type: application/json`
  - `apikey: <Supabase anon/public key>`
  - `Authorization: Bearer <agent's JWT access token>`
- Request parameter names are prefixed `p_`, matching the existing
  `agent_get_tasks`/`agent_update_task`/`agent_enqueue_audit_logs`
  convention exactly (PostgREST maps `p_foo` JSON keys onto a Postgres
  function's `p_foo` parameter).
- A 401 means the token is expired or invalid; the agent already retries
  once after a token refresh (`authsvc.Service.DoWithAuthRetry`) before
  giving up — no different handling is needed here.
- A 404 or 501 on any of these functions is read by the agent as "this
  function does not exist on this backend" and causes it to latch to the v1
  transport for the remainder of the agent process's run (see
  `internal/epm/transportbe/negotiate.go`). Until these functions are
  deployed, every backend will correctly produce this response by default
  (an unknown RPC name 404s), which is exactly the fallback behavior wanted.

## 1. `agent_epm_get_policy`

Fetches the next pending policy update for the calling device, if any.

**Request**

```json
{ "p_cursor_generation": 41 }
```

`p_cursor_generation` is the `generation` of the last bundle this device
successfully applied (see `internal/epm/bundle.go`'s `PolicyBundle.Generation`
— a monotonic per-tenant counter already established in Phase 3). `0` means
the device has applied nothing yet; the function should return the latest
full bundle for the device's device group / tenant in that case.

**Response — 200, something pending**

```json
{
  "bundle": {
    "payload": "<base64 or raw JSON-encoded PolicyBundle — see below>",
    "alg": "ed25519",
    "key_id": "prod-2026-01",
    "sig": "<base64 detached signature over payload's exact bytes>"
  }
}
```

`bundle` is the agent's existing `epm.SignedBundle` shape
(`internal/epm/bundle.go`), unchanged from Phase 3: `payload` is the exact
byte sequence that was signed (a serialized `PolicyBundle`), never a
re-derived or re-marshalled form of it — the agent verifies the signature
against those literal bytes (`internal/epm/bundle_verify.go`). See
`internal/epm/bundle.go`'s `PolicyBundle` struct for the payload's own JSON
shape (`schema_version`, `bundle_id`, `generation`, `mode`, `rules`, etc.) —
that shape is unchanged by this document.

**Response — 200, nothing newer than the cursor**

```json
{ "bundle": null }
```

**Response — 404 / 501**

Not implemented on this backend. The agent latches to v1 for the rest of
the run.

## 2. `agent_epm_ack_policy`

Reports whether a fetched bundle was successfully applied.

**Request**

```json
{
  "p_bundle_id": "b-2026-01-29-0007",
  "p_applied": true,
  "p_note": "activated at generation 42"
}
```

`p_applied: false` means compilation, signature verification, or the
bundle's own canary suite (`internal/epm/bundle_manager.go`'s
`BundleManager.Apply`) rejected it — `p_note` carries the human-readable
reason in that case, mirroring what `agent_update_task`'s `p_note` already
does for a failed task.

**Response — 200**

Empty body. The agent does not read anything back from this call.

## 3. `agent_epm_enqueue_events`

Uploads audit rows and/or process-monitor events. A single endpoint serves
both `EventTransport.SendAudit` and `EventTransport.SendProcessEvents` — the
agent calls it once per row batch with only the relevant field populated.

**Request — audit rows**

```json
{
  "p_audit_rows": [
    {
      "ID": 101,
      "Entry": { "...": "the existing epm.AuditEntry shape, unchanged — see internal/epm/audit.go" }
    }
  ]
}
```

**Request — process events**

```json
{
  "p_process_events": [
    { "ObservedAtUnix": 1774950000, "EventData": "<pre-marshalled JSON of one procmon.ProcessEvent>" }
  ]
}
```

Both fields are `omitempty`; a given call populates exactly one of them.

**Response — 200**

Empty body. Retried on 5xx/network failure with the agent's existing
exponential-backoff enqueue policy (`rpcutil.WithEnqueueRetry` — 1s initial
delay, 5 min cap, 10 attempts); a 4xx other than 401 is treated as a
permanent rejection and the batch is dropped rather than retried forever.

## 4. `agent_epm_submit_approval`

Submits a `RequireApproval`-verdict elevation request for human review, once
Phase 5's session helper has collected a justification from the user.

**Request**

```json
{
  "p_request_id": "6f2b...-uuid",
  "p_rule_id": "rule-42",
  "p_user_id": "alice@corp.example.com",
  "p_app_path": "C:\\Tools\\admin-console.exe",
  "p_justification": "Deploying hotfix per INC-1234"
}
```

**Response — 200**

```json
{ "approval_id": "appr-9f21" }
```

## 5. `agent_epm_poll_approvals`

Polls the status of one or more previously submitted approvals. This is
deliberately two-phase rather than a held-open connection: approval can take
minutes to hours (a human has to act on it), and the agent's elevation
connections are not held open that long — see
`internal/epm/protocol.go`'s `OpApprovalPoll` and the Phase 2 design notes
in `internal/epm/server.go` for why.

**Request**

```json
{ "p_approval_ids": ["appr-9f21", "appr-a044"] }
```

**Response — 200**

```json
{
  "approvals": [
    { "approval_id": "appr-9f21", "status": "approved", "note": "" },
    { "approval_id": "appr-a044", "status": "pending", "note": "" }
  ]
}
```

`status` is one of `pending` | `approved` | `denied` | `expired`. The agent
polls at an interval Phase 5's session helper controls; this document does
not prescribe one.

## What is explicitly out of scope here

- **No backend implementation.** This is a specification, not a working
  endpoint — see the status line at the top.
- **No policy application through this transport yet.** `main_integration.go`
  constructs a `Negotiator` and consults it once per `epm-policy-sync` cycle
  (so `Probe` genuinely calls `agent_epm_get_policy`), but actual rule
  fetch/apply/ack still goes exclusively through the v1 task-payload
  piggyback; `epm-audit-sync` is entirely unmodified. Routing real policy
  retrieval and event upload through this transport is a separate, later
  change that also requires wiring `BundleManager` into `epm.Server`'s rule
  source, once a real v2 backend exists to negotiate against.
- **Authentication/authorization model.** Assumed identical to every other
  agent RPC (Supabase JWT + RLS keyed on the device's identity) — nothing
  here introduces a new auth mechanism.
- **Rate limiting / abuse prevention** on the backend side is a backend
  concern this document does not specify.
