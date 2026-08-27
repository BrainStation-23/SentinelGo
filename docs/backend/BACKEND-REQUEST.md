# Backend Request — SentinelGo Telemetry Layer

*A self-contained brief for the SentinelOps backend team or an agent working in
the SentinelOps repository. Copy the section below verbatim.*

---

## Subject: SentinelGo telemetry layer — backend readiness audit and implementation request

### 1. Context

The SentinelGo endpoint agent (separate repository) has completed an additive
**telemetry layer**. It collects OS-level inventory and security posture across
Windows, Linux and macOS and reports it through Supabase RPCs.

The agent side is code-complete and tested. It is **shipped disabled** and will
stay disabled until this backend side is confirmed. Nothing described here is
live yet, and no production data is at risk today.

**Before anything else, please tell us what already exists.** We are not
assuming this backend is missing these objects — we cannot see your repository
and are asking, not asserting. For every item below, answer one of:

- **EXISTS** — already implemented, with a pointer to the migration/function
- **PARTIAL** — exists but behaves differently (say how)
- **MISSING** — needs to be built

### 2. What the agent already uses today (unchanged, for orientation)

These are working and are **not** part of this request. They are listed so you
can locate the pattern the new endpoints should follow:

- `agent-login` edge function
- `agent_enqueue_inventory`, `agent_enqueue_software`, `agent_enqueue_services`,
  `agent_enqueue_audit_logs`
- `get_latest_agent_release`

Auth is unchanged: agent JWT in `Authorization: Bearer …` plus the `apikey`
header.

### 3. What is being added — two new RPCs

| RPC | Purpose | Required for |
|---|---|---|
| `agent_enqueue_telemetry` | Section telemetry — inventory, posture and health classes | **Everything.** The layer cannot ship without it |
| `agent_enqueue_telemetry_events` | Change events — dated state transitions | Only if change detection is enabled |

Both are `POST /rest/v1/rpc/<name>` with a JSON body `{"payload": {...}}`.
A `2xx` is treated as accepted. The agent parses `{"msg_id": <int>, "queue":
"<string>"}` if present but does not require it.

### 4. How it works, and what depends on the backend behaving correctly

Please read this section before estimating. Three of these behaviours will
silently corrupt data if implemented the obvious way rather than the specified
way.

#### 4.1 `sections` means MERGE, never REPLACE — highest risk item

The agent deliberately sends **only the sections whose reconcile clock is due**,
not the whole device state each time. Static hardware reconciles every 24 hours;
security posture every hour. This is the mechanism that removes roughly
**230,000 uploads of unchanged data per day across a 10,000-endpoint fleet**.

Consequence: a payload containing three sections is **not** a statement that the
device has only three sections. If the backend replaces the row set per request,
every section absent from that request is deleted, and each device appears to
lose most of its inventory every cycle.

This failure produces **no error anywhere** — only plausible-looking wrong data.
Please implement per-section upsert keyed on `(device_id, section)`.

An envelope field `full_snapshot: true` indicates the rare case where the cycle
did carry every section; only then is reconciling deletions safe.

#### 4.2 Retries replay identical bytes — you must deduplicate

The agent stores the complete serialised request body and replays it **byte for
byte** on retry, including `snapshot_id`, `batch_index` and `batch_count`. A
network retry must therefore not create a second logical snapshot.

Please deduplicate on `(device_id, snapshot_id, section, batch_index)`.

There is also a monotonic `collection_generation` per device that survives agent
restarts. If out-of-order arrival is possible in your queue, use it to reject a
stale payload overwriting a newer one.

#### 4.3 Chunked sections must be assembled before they are applied

Five sections split across multiple messages rather than truncating:
`processes`, `certificates`, `persistence`, `patches`, `routes`.

Each carries `chunk: { snapshot_id, batch_index, batch_count, total_items,
truncated, excluded_items }`. `batch_index` is 0-based.

The section must be applied **only once all `batch_count` chunks have arrived**.
A partially assembled process list applied as-is reads as "most processes on
this machine stopped". Incomplete assemblies need a discard timeout — see the
open questions.

#### 4.4 Capability states are the point of the design

Per capability key, the agent reports **why** data is or is not present. Six
states, which must be stored verbatim and kept distinct:

`supported`, `not_present`, `unsupported`, `disabled`, `unavailable_on_os`,
`not_collected`

The critical pair is the last two. `not_collected` means "this agent build ships
no collector for it" — an agent-side gap, fixable by shipping a collector.
`unavailable_on_os` means "this operating system genuinely cannot provide it" —
a platform fact. Collapsing them tells an operator to stop investigating
something that is actually fixable.

Without these states, "this desktop has no battery", "an administrator switched
the collector off" and "collection crashed" all arrive as the same empty field.

Keys currently in use: `storage.smart`, `storage.encryption`, `patch_inventory`,
`sessions`, `processes`, `processes.cmdline`, `battery_detail`, `tpm`,
`secure_boot`, `certificates`, `directory_join`, `network.routing_table`,
`persistence`, `peripherals.usb`, `virtualization`, `security.firewall`,
`security.realtime_protection`, `security.tamper_protection`.

Upsert per `(device_id, capability_key)`.

#### 4.5 Change events need idempotency on `event_id`

Events are dated, immutable assertions that one tracked value moved from A to B
— "BitLocker was disabled at 14:22", not "BitLocker is disabled". They are
append-only and are never overwritten.

`event_id` is **deterministic**: derived from the device, the watched value and
the transition. A retried delivery carries the **same** id. Without a unique
constraint on it, one network retry produces two "BitLocker was disabled"
alerts.

Event fields: `event_id`, `event_type`, `section`, `priority`, `severity`,
`occurred_at`, `detected_at`, `previous_value`, `current_value`,
`schema_version`.

`priority` is an integer, ascending-urgent: `0` critical, `10` high, `50`
normal, `80` low. `previous_value` and `current_value` are opaque JSON whose
shape varies by watched value (scalar, set summary, or membership) — please
store them as JSON rather than coercing to text.

Values currently watched: hostname, domain join, Entra join, BitLocker protected
volumes, pending reboot, installed patches, Secure Boot state, firewall state,
real-time protection, tamper protection, privileged accounts.

### 5. Section names

22 names. They are contract: additions are fine, renames are not.

```
identity            virtualization      directory           firmware
tpm                 cpu                 memory_modules      physical_disks
os                  volumes             network             routes
sessions            security_posture    encryption          secure_boot
security_protection patches             persistence         processes
certificates        health
```

`health` is sampled rather than reconciled — it is never fingerprinted and may
be given its own retention or aggregated away.

Please **accept an unknown section name without rejecting the whole payload**. A
newer agent in a mixed fleet will send names an older backend does not know;
rejecting the request loses the known sections too.

### 6. Reference material in the agent repository

- `docs/backend/backend-compatibility-checklist.md` — the same items as a
  point-by-point checklist, each marked REQUIRED / OPTIONAL / VERIFY
- `docs/backend/telemetry-contracts.md` — full payload shapes, envelope fields,
  merge and chunk-assembly semantics, and **reference DDL** you can adapt

### 7. Four questions only you can answer

We have deliberately not guessed at these. Please answer each.

1. **Does the enqueue path accept `Content-Encoding: gzip` on request bodies?**
   Measured on a real Windows endpoint, gzip cut one collection cycle from
   **105,867 bytes to 18,007 — 83%**. The agent has this implemented and
   **shipped disabled**; it will not be enabled until you confirm, because if
   the backend does not decompress, every telemetry upload becomes a 4xx.

2. **What is the actual maximum request body size?** The agent currently assumes
   1 MB and caps payloads at 900 KB. Confirm or correct.

3. **What chunk-assembly timeout should we assume?** We propose 15 minutes. The
   agent's retry window must sit inside whatever you choose, or a slow retry
   lands after the partial assembly has been discarded.

4. **Is point-in-time section history required, or is current state sufficient?**
   The agent assumes current state only. If history is wanted, a separate
   append-only table with its own retention is a better fit than keeping every
   snapshot in the main table.

### 8. Suggested retention (your policy call, not an agent requirement)

| Table | Suggested |
|---|---|
| section state | current state only |
| capability state | current state only |
| run/diagnostics | 30 days — highest volume, diagnostics not inventory |
| chunk buffer | 15 minutes — transient |
| events | 1 year for critical, 90 days otherwise |

### 9. Alerting integration

Routing is your decision; the agent only classifies. A reasonable starting rule
is to route `priority <= 10` (critical and high) to the alert engine —
`secure_boot.state`, firewall, real-time protection, tamper protection and
BitLocker transitions land there.

### 10. Acceptance test sequence

We will run these against a staging project before enabling anything. Steps 1–4
are the gate for turning the agent's telemetry on at all.

1. `agent_enqueue_telemetry` accepts a single-section payload → 2xx
2. A second payload carrying a **different** section leaves the first intact
   *(the merge check from §4.1 — the one that fails silently)*
3. Capability states round-trip, with `not_collected` and `unavailable_on_os`
   still distinguishable
4. A chunked section (`processes`) assembles correctly across batches and is not
   applied until complete
5. Replaying an identical payload does not create a duplicate snapshot
6. `agent_enqueue_telemetry_events` accepts an event; replaying the same
   `event_id` does not create a second row
7. Questions 1–4 in §7 answered

### 11. What we need back

1. **EXISTS / PARTIAL / MISSING** for each of: the two RPCs, merge semantics,
   the section and capability tables, chunk assembly, event idempotency
2. **Answers to the four questions in §7**
3. **An estimate** for whatever is MISSING
4. **A staging endpoint** we can run the acceptance sequence against

Until items 1–4 of §10 pass, the agent keeps `telemetry_enabled: false` and
sends nothing new. There is no deadline pressure from our side and no risk to
current production traffic — the existing inventory, software, services and
audit-log pipelines are untouched by this work.
