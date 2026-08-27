# SentinelOps Backend Compatibility Checklist

**Audience:** whoever maintains the SentinelOps backend.
**Scope:** what that backend must provide for the SentinelGo telemetry layer to
deliver data, derived by reading the agent's own sender and collectors.

**This is a compatibility checklist, not a status report.** The SentinelOps
backend lives in a separate repository. Nothing here asserts what it does or
does not already implement — those columns are for the backend owner to fill in.
Where the agent needs an answer it cannot determine from its own side, the item
is marked **requires backend verification** and is left unanswered rather than
guessed at.

Companion documents: [telemetry-contracts.md](telemetry-contracts.md) has the
full payload shapes and reference DDL; this file is the point-by-point list.

---

## Legend

| Mark | Meaning |
|---|---|
| **REQUIRED** | Without it the agent cannot deliver that data at all |
| **OPTIONAL** | An optimisation or convenience; the agent works without it |
| **VERIFY** | The agent cannot determine this from its side — needs an answer from the backend |

---

## 1. RPC endpoints

| # | Item | Status | Detail |
|---|---|---|---|
| 1.1 | `POST /rest/v1/rpc/agent_enqueue_telemetry` | **REQUIRED** | Section telemetry: the `inventory`, `posture` and `health` classes |
| 1.2 | `POST /rest/v1/rpc/agent_enqueue_telemetry_events` | **REQUIRED** for Phase G | Change events only. Needed only if `telemetry_events_enabled` is turned on |
| 1.3 | Both accept `Authorization: Bearer <agent JWT>` + `apikey` | **REQUIRED** | Same auth as the existing `agent_enqueue_*` RPCs |
| 1.4 | Both return `{ "msg_id": <int>, "queue": "<name>" }` | **OPTIONAL** | The agent logs it; a 2xx with an unparseable body is still treated as success |

**Why 1.1 and 1.2 are separate.** A section row is current state and gets
overwritten; an event is a dated assertion that something changed and is kept for
a year. Routing both through one RPC would force the backend to demultiplex on
payload shape.

### What happens if an endpoint is missing

A missing RPC answers **404**. The agent classifies any non-401 4xx as a
rejection: the message is retained in the local queue, logged, counted, written
to the emergency log, and **dead-lettered after 5 attempts**. Nothing is lost,
but nothing is delivered, and the condition is only visible in agent logs and
`-telemetry-health`. **This is why telemetry must stay disabled until 1.1 is
confirmed live.**

## 2. Merge semantics — the one that silently corrupts data

| # | Item | Status | Detail |
|---|---|---|---|
| 2.1 | `sections` means **MERGE, not REPLACE** | **REQUIRED** | ⚠️ See below |
| 2.2 | Absent section ≠ deleted section | **REQUIRED** | A section missing from a payload means "not collected this cycle", never "no longer present" |
| 2.3 | Per-section upsert keyed on `(device_id, section)` | **REQUIRED** | |

⚠️ **This is the highest-risk item on the list.** The agent sends only the
sections whose reconcile clock is due — that is the entire point of separating
collect and reconcile intervals, and it is what removes ~230,000 uploads of
unchanged data per day at 10,000 endpoints. A backend that replaces the whole
row set on each payload would therefore **delete every section not present in
that request**, and a device would appear to lose most of its inventory every
cycle. Getting this wrong does not produce an error anywhere; it produces
plausible-looking wrong data.

## 3. Section names

The agent emits these 22 section names. They are part of the contract: add,
never rename.

| # | Item | Status | Detail |
|---|---|---|---|
| 3.1 | Accept all 22 names below | **REQUIRED** | |
| 3.2 | Accept an unknown section name without failing the whole payload | **OPTIONAL** but strongly advised | A newer agent in a mixed fleet will send names an older backend does not know. Rejecting the payload loses the known sections too |

```
identity            virtualization      directory           firmware
tpm                 cpu                 memory_modules      physical_disks
os                  volumes             network             routes
sessions            security_posture    encryption          secure_boot
security_protection patches             persistence         processes
certificates        health
```

`health` is sampled, never fingerprinted and never reconciled; it may be stored
with its own retention or discarded after aggregation.

## 4. Capability states

The agent reports, per capability key, why data is or is not present. The
distinction is the point: without it, "this desktop has no battery", "an admin
switched the collector off" and "collection crashed" all arrive as the same
empty field.

| # | Item | Status | Detail |
|---|---|---|---|
| 4.1 | Store all six states verbatim | **REQUIRED** | `supported`, `not_present`, `unsupported`, `disabled`, `unavailable_on_os`, `not_collected` |
| 4.2 | Treat **`not_collected`** as distinct from `unavailable_on_os` | **REQUIRED** | `not_collected` = "this agent build ships no collector for it"; `unavailable_on_os` = "this OS genuinely cannot provide it". An operator seeing the latter stops investigating |
| 4.3 | Capability keys are upserted per `(device_id, key)` | **REQUIRED** | |
| 4.4 | Surface capability state in the device UI | **OPTIONAL** | The states are only useful if an operator can see them |

All 18 keys are claimed by a collector except `peripherals.usb`, which
correctly reports `not_collected` — no collector ships for it.

Current keys: `storage.smart`, `storage.encryption`, `patch_inventory`,
`sessions`, `processes`, `processes.cmdline`, `battery_detail`, `tpm`,
`secure_boot`, `certificates`, `directory_join`, `network.routing_table`,
`persistence`, `peripherals.usb`, `virtualization`, `security.firewall`,
`security.realtime_protection`, `security.tamper_protection`.

## 5. Chunk assembly

Sections registered as chunked — `processes`, `certificates`, `persistence`,
`patches`, `routes` — are split into multiple messages rather than truncated.

| # | Item | Status | Detail |
|---|---|---|---|
| 5.1 | Assemble chunks before applying a section | **REQUIRED** for those five sections | Keyed on `(device_id, snapshot_id, section)` |
| 5.2 | Honour `chunk.batch_index` / `chunk.batch_count` | **REQUIRED** | Both 0-based index and total are in every chunked message |
| 5.3 | Apply the section only once all `batch_count` chunks have arrived | **REQUIRED** | A partially assembled process list applied as-is reads as "most processes stopped" |
| 5.4 | Discard an incomplete assembly after a timeout | **REQUIRED** | Chunk assembly timeout — see 8.3 |
| 5.5 | Record `chunk.truncated` / `chunk.excluded_items` | **OPTIONAL** | The agent reports when a hard item cap was hit |

Chunk metadata fields: `snapshot_id`, `batch_index`, `batch_count`,
`total_items`, `truncated`, `excluded_items`.

## 6. Snapshot authority and idempotency

| # | Item | Status | Detail |
|---|---|---|---|
| 6.1 | Retries are replays, not new snapshots | **REQUIRED** | The agent stores the complete request body and replays **identical bytes** on retry, including `snapshot_id`, `batch_index` and `batch_count`. Deduplicate on `(device_id, snapshot_id, section, batch_index)` |
| 6.2 | `collection_generation` is monotonic per device | **REQUIRED** if out-of-order arrival is possible | Increments per collection cycle; survives restart. Use it to reject a stale payload overwriting a newer one |
| 6.3 | `full_snapshot: true` means every section in this cycle is present | **OPTIONAL** | Lets the backend safely reconcile deletions |
| 6.4 | `schema_version` / `section_versions` respected per section | **OPTIONAL** but advised | Lets a section's shape change without breaking older stored rows |

## 7. Change events (Phase G)

Event payload fields: `event_id`, `event_type`, `section`, `priority`,
`severity`, `occurred_at`, `detected_at`, `previous_value`, `current_value`,
`schema_version`.

| # | Item | Status | Detail |
|---|---|---|---|
| 7.1 | **Idempotency on `event_id`** | **REQUIRED** | ⚠️ `event_id` is deterministic, derived from the device, the watched value and the transition — a retried delivery carries the SAME id. Without a unique constraint on it, one network retry produces two "BitLocker was disabled" alerts |
| 7.2 | Event rows are append-only, never overwritten | **REQUIRED** | An event is a dated assertion, not current state |
| 7.3 | Store `priority` as an integer, ascending-urgent | **REQUIRED** | `0` critical, `10` high, `50` normal, `80` low |
| 7.4 | Retain critical events for 1 year, others 90 days | **OPTIONAL** (policy) | Proposal, not an agent requirement |
| 7.5 | Alert-engine integration: route `priority <= 10` to alerting | **OPTIONAL** | The agent classifies; what to alert on is a backend policy decision |
| 7.6 | Delivering an event must not mark a section reconciled | **REQUIRED** | Events carry no sections. The agent enforces this on its side too |
| 7.7 | Preserve `previous_value` / `current_value` as opaque JSON | **REQUIRED** | Shape varies by watched value: scalar, set summary, or membership |

Watched values currently emitting events: `identity.hostname`,
`directory.domain_joined`, `directory.entra_joined`,
`encryption.protected_volumes`, `os.pending_reboot`, `patches.installed`,
`secure_boot.state`, `security_protection.firewall.state`,
`security_protection.realtime_protection.state`,
`security_protection.tamper_protection.state`,
`security_posture.privileged_accounts`.

## 8. Open questions — **requires backend verification**

These four cannot be answered from the agent side. They are recorded unanswered
on purpose.

| # | Question | Why it matters | Agent's current assumption |
|---|---|---|---|
| 8.1 | **Does the enqueue path accept `Content-Encoding: gzip`?** | Measured on a real Windows endpoint: over the 20 sections that host populated, gzip cut **105,867 bytes to 18,007 — 83%**. Large sections benefit most (processes 86%, routes 90%, certificates 79%); sections under ~100 bytes get *bigger*, so the agent only compresses bodies ≥ 1 KiB | Implemented, **shipped disabled** (`telemetry_gzip_enabled: false`). Must not be enabled until this is answered — if the backend does not decompress, every upload becomes a 4xx |
| 8.2 | **What is the actual maximum request body size?** | Determines chunk sizing | Assumes 1 MB, caps payloads at **900 KB** |
| 8.3 | **What is the chunk assembly timeout?** | The agent's retry window must sit inside it, or a slow retry lands after the partial assembly was discarded | Proposes **15 minutes**; no agent-side value depends on it yet |
| 8.4 | **Is point-in-time section history needed, or is current state sufficient?** | Changes the storage model | Assumes current state only; history, if wanted, is better served by a separate append-only table |

## 9. Verification order

Recommended sequence once the backend side is ready. **Do not enable telemetry
against production until at least steps 1–4 pass.**

1. `agent_enqueue_telemetry` accepts a single-section payload and returns 2xx
2. A second payload with a **different** section leaves the first one intact
   (item 2.1 — the merge check)
3. Capability states round-trip, including `not_collected`
4. A chunked section (`processes`) assembles correctly across batches
5. A replayed identical payload does not create a duplicate snapshot (6.1)
6. `agent_enqueue_telemetry_events` accepts an event; a replay of the same
   `event_id` does not create a second row (7.1)
7. Answer 8.1–8.4

## 10. Agent-side settings that depend on these answers

| Setting | Default | Change only after |
|---|---|---|
| `telemetry_enabled` | `false` | steps 1–4 above pass |
| `telemetry_events_enabled` | `false` | step 6 passes |
| `telemetry_gzip_enabled` | `false` | 8.1 is answered yes |
| `collect_routing_table` | `false` | telemetry is live and the extra section is wanted |
| `processes_collect_cmdline` | `false` | a privacy review — command lines carry tokens and passwords |
