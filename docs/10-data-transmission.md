# Data Transmission: What Gets Sent, When

What SentinelGo actually sends to Supabase, on what clock, at what approximate
size, and what happens when a send fails. Traced directly from
`internal/scheduler`, `internal/service`, `internal/osinfo`, `internal/logging`,
and `internal/updater` at commit `7caad9d` (2026-09-28).

> A visual version of this document (log-scale payload chart, payload
> composition breakdown, and a vertical 24-hour timeline) is published as a
> Claude artifact. It's private by default — share it from its page's Share
> menu if your team needs the link.

There is no dedicated "heartbeat" package. Everything runs inside one
long-lived agent process (`cmd/sentinelgo`), driven by a generic task
`Scheduler` (`internal/scheduler/scheduler.go`). The closest thing to a
heartbeat is the `agent-info-update` task (inventory upload).

## Known discrepancy in the source

`AgentInfoUpdateInterval`'s own doc-comment says the default is `1h`
("how often to push inventory to Supabase") — `internal/config/config.go:95`.
But `Load()` (`config.go:214`) and the getter's zero-value fallback
(`config.go:165-170`) both actually set `5 * time.Minute`. This document
follows the code's real behavior (5-minute tick, 1-hour forced-resend
ceiling), not the comment. Worth fixing the comment or the default, whichever
was intended.

## Scheduled tasks and default intervals

| Task | Default interval | Config field | Notes |
|---|---|---|---|
| `token-refresh` | 1 min (hardcoded) | — | Almost always a no-op; see below |
| `agent-info-update` (heartbeat/inventory) | 5 min | `AgentInfoUpdateInterval` | Only *sends* if changed or ≥1h since last send |
| `software-sync` | 5 min | `UpdateInterval` | |
| `services-collect` | 5 min | `ServicesUpdateInterval` | |
| `auto-update` | 1 hr (+ up to 5 min jitter) | `AutoUpdateInterval` | Metadata check only; binary fetch is conditional |
| audit-log flush | 5 min | `LogFlushInterval` | Plus a continuous real-time stream (not on a tick) |

Sources: `internal/scheduler/scheduler.go:477-511` (`CreateDefaultTasks`),
`internal/main_integration.go:166-216`, `internal/config/config.go:207-226`.

Every task except `token-refresh` gets a random startup delay in `[0, interval)`
the first time it fires, so a fleet of agents restarted together doesn't all
call home in the same second (`scheduler.go:322-337`). Heartbeat,
software-sync, and services-collect additionally run once immediately at
startup, in dependency order, before their tickers take over
(`scheduler.go:265-307`).

## Payload sizes

All "estimated" figures are derived from the actual Go struct field list, not
a captured wire payload — treat them as order-of-magnitude. "Hard limit"
figures come straight from a constant in code.

| Request | Size | Confidence |
|---|---|---|
| Update metadata check (`get_latest_agent_release` RPC) | ~350 B | estimated |
| Auth token exchange (`agent-login` / refresh) | ~1.2 KB | estimated |
| Heartbeat — best case | ~4.8 KB (4–6 KB range) | estimated |
| Heartbeat — worst case | ~20.5 KB (up to ~35 KB) | estimated |
| Audit-log batch | ≤ 900,000 bytes, ≤ 100 rows | **hard limit** (`internal/logging/uploader.go:17-18`) |
| Update binary download | 10–30 MB | estimated (code comment: "~18 MB+") |

A log-scale comparison matters here: linear, the update binary would make
every other request invisible on the same axis.

### Heartbeat payload anatomy

`AgentUpdatePayload` (`internal/service/agent/agent.go:25-50`) is a *subset*
of the full `shared.SystemInfo` collected by `osinfo.Collect()` — CPU/memory/
disk usage counters and a few other fields are collected but never sent in
this payload. Rough composition:

| Component | Best case | Worst case |
|---|---|---|
| Security & compliance (`security_info`: AV, firewall, encryption, EDR/XDR, listening ports) | ~2.0 KB | ~11.5 KB |
| Hardware & network inventory (adapters, disks, GPUs, displays, peripherals, printers, audio) | ~1.2 KB | ~5.75 KB |
| System identity & OS info (hostname, CPU, RAM, `os_information`) | ~1.4 KB | ~1.75 KB |
| Users & accounts (`local_users`) | ~0.2 KB | ~1.5 KB |
| **Total** | **~4.8 KB** | **~20.5 KB** |

`security_info` is the single biggest lever on size: a host with several
antivirus/EDR products installed and many listening ports can push this
component alone past 10 KB. Sources: `agent.go:25-50`,
`internal/osinfo/shared/types.go:234-457`.

## The 24-hour trace

### 00:00 — boot

1. **Connectivity probe + login.** TCP dial + HTTP GET to confirm the network
   is up, then `POST /functions/v1/agent-login` with
   `{agent_id, agent_secret}`. Response: `{access_token, refresh_token, expires_in}`.
   A still-valid stored token (≥5 min left) skips this and reuses it.
   (`main_integration.go:140-155`, `login.go:23-46`)
2. **Startup update check** — async, best-effort, only if `auto_update` is
   enabled. Small metadata call (~350 B). (`main_integration.go:123-133`)
3. **Scheduler starts all 5 tasks**, each with its own startup jitter (except
   token-refresh). Heartbeat, software-sync, and services-collect also run
   once immediately. (`scheduler.go:322-337, 265-307`)
4. **First heartbeat send** — always transmits, since there's no prior
   fingerprint to compare against. 4.8–20+ KB depending on the host.

### Every 1 minute — token-refresh (mostly silent)

Fires 1,440×/day but only makes a network call when the token is unparseable,
expired, or within 5 minutes of expiry. Nearly every tick is a no-op. A 401 on
*any other* call triggers recovery immediately, independent of this clock.
(`scheduler.go:484, 517`, `jwt.go:47-58`)

### Every 5 minutes — collect always, send sometimes

- **Heartbeat/inventory**: re-collects the full snapshot every tick (bounded
  by a 90s timeout) but only *transmits* it if a SHA-256 fingerprint of the
  stable fields changed, or an hour has passed since the last send — whichever
  comes first. (`scheduler.go:556-598, 29`)
- **Software-sync** and **services-collect** run on the same clock without
  that gate.
- **Audit-log flush**: scheduled upload of whatever's queued, capped at
  ≤100 rows / ≤900 KB per batch.
- **Continuous, not on a tick**: a separate real-time path streams
  high-priority OS events straight into the local queue the instant they
  happen, independent of the 5-minute flush. (`logging.go:234-267`)

### Every hour — the two things that only happen hourly

- **Auto-update check**: asks Supabase for the latest release metadata
  (version, SHA-256, size, storage path) — a small RPC, plus up to 5 minutes
  of extra jitter on top of the hourly tick. (`checker.go:24-32, 168-196`,
  `scheduler.go:539-550`)
- **Heartbeat force-resend**: fires regardless of the fingerprint, so state
  never goes stale for more than an hour even on a perfectly quiet machine.
  (`scheduler.go:29`)

Hours 2–23 repeat this pattern exactly — the 5-minute cluster and the hourly
mark — with no new behavior, except wherever a failure actually occurs (next
section).

### Day total (approximate)

- ≥24 heartbeat sends — one forced per hour minimum, more if anything changed
- ~288 sync & audit-flush ticks — one every 5 minutes, all day
- ~1,440 token-refresh checks, almost all silent
- ~24 update-metadata checks, each under 1 KB
- A 10–30 MB binary download is **not** part of this clock at all — it
  happens once, only on whichever day a newer version is actually published

## Failure handling

### RPC-level retry policy

Shared by inventory upload, audit-log upload, and software/services sync
(`internal/service/rpcutil/enqueue_retry.go`):

| Response | Behavior |
|---|---|
| 2xx | Success |
| 401 | Propagated to the caller's `DoWithAuthRetry`, which recovers the session and retries once |
| Other 4xx | Logged and **dropped** — "server rejected the payload, retrying won't help" (no retry) |
| 5xx / network error | Exponential backoff — base 1s, doubling, capped at 5 min, with jitter — retried until the caller's own context times out (60s for a heartbeat) |

Sources: `enqueue_retry.go:12-15, 26-58, 61-75`.

### Auth circuit breaker

`Service.DoWithAuthRetry` runs a call once; on 401 it calls `Recover()`
(refresh, or fallback to full login), single-flighted, then retries the call
exactly once more. `Recover()` itself is gated by a circuit breaker: 5
consecutive failures open it for 5 minutes, after which one half-open trial
is allowed. While the breaker is open, every reporting task (heartbeat,
sync, services, audit-upload) explicitly **skips its cycle** rather than
firing a call it knows will 401. (`auth.go:29-31, 76, 293-305`,
`scheduler.go:559-565`)

### What happens to data during an outage

| Data | Buffered? | Behavior |
|---|---|---|
| **Audit logs** | **Yes** | Every collected entry is durably inserted into a local SQLite queue *before* upload is attempted. A failed batch simply stays queued and retries next flush cycle — nothing is dropped on a transient failure. This is deliberate: it's a compliance agent, audit events must not silently disappear. (`logging.go:279-289`) |
| **Heartbeat / inventory** | No | Recomputed fresh every cycle. A failed send is retried within that same call (backoff above); if the whole tick still fails, the *next* scheduled tick just re-collects and re-sends current state. No queue of missed historical snapshots — only the latest state is ever sent. |
| **Software/services sync** | No | Same as heartbeat — recomputed and re-sent next cycle, no historical buffering. |
| **Updater** | N/A | Stateless check-then-fetch each cycle. `CheckAndApplyWithRetry` retries within one invocation (3 attempts, backoff 5s→doubling→capped 5 min); the next scheduled tick (~1h+jitter later) tries again if that also failed. A backup copy + rollback protects against a bad binary swap. |

### Illustrative outage sequence

1. Supabase becomes unreachable — heartbeat, sync, and audit-upload RPCs all
   return network errors instead of 2xx.
2. Each call backs off exponentially (1s → 2s → 4s → … capped at 5 min,
   jittered) and keeps retrying until its own timeout expires.
3. After 5 consecutive auth-recovery failures, the circuit breaker opens for
   5 minutes. Every reporting task skips its cycle while it's open.
4. Audit-log collection never stops — everything keeps queuing to local
   SQLite.
5. Heartbeat and sync are not queued — no backlog to replay, just eventual
   consistency once a cycle succeeds again.
6. Connectivity returns → the breaker's half-open trial succeeds → it closes.
   The next tick sends a forced heartbeat (>1h will have elapsed) and the
   audit uploader drains its backlog in ≤100-row / ≤900 KB batches until
   empty.

## Not part of this flow

`internal/lockfile` implements a full PID-lock file with staleness detection,
but is never imported outside its own test file — it's dead code and plays no
role in scheduling, retries, or data transmission.

## References

- `internal/scheduler/scheduler.go` — task definitions, jitter, fingerprint
  gate, force-resend, circuit-breaker gating
- `internal/main_integration.go` — startup sequence, config wiring
- `internal/config/config.go` — defaults and getters (see discrepancy note above)
- `internal/service/agent/agent.go` — `AgentUpdatePayload`, inventory RPC
- `internal/osinfo/collect.go`, `internal/osinfo/shared/types.go` — full
  `SystemInfo` collection and `SecurityInfo` shape
- `internal/service/auth/` — login, refresh, circuit breaker
- `internal/updater/checker.go`, `downloader.go` — release check, binary
  download, retry/backoff, backup/rollback
- `internal/logging/`, `internal/auditlogs/` — collection loop, real-time
  stream, batching/upload
- `internal/service/rpcutil/enqueue_retry.go` — shared RPC retry policy
