# 04 — Telemetry Architecture

*Deliverables 6–11: data model, change detection, local state, intervals, and what to extend versus build new.*

## Governing constraint: additive only

The existing scheduler, collectors, local stores, transport, authentication, software/services pipelines and audit-logging pipeline are **stable foundations and are not modified**. The telemetry layer is built around them:

- `osinfo.Collect()`, `shared.SystemInfo`, `AgentUpdatePayload`, `sysInfoFingerprint`, `agentInfoForceResend`, the scheduler internals, `internal/logging/`, `internal/auditlogs/` and `internal/service/{auth,software,services,agent}` are untouched.
- The new layer reuses existing code by **calling it read-only**, never by editing it.
- It registers **one** task through the same public path `services-collect` uses.
- New helpers sit alongside old ones — `RunCommandContext` next to `RunCommand` — with no existing function rewritten.

Accepted cost: some transitional overlap on the wire, for example disks appearing in both the legacy inventory payload and a new `storage` section. Consolidation is deferred to [06-existing-code-observations.md](06-existing-code-observations.md).

---

## 1. Package layout

```
internal/telemetry/          domain layer — no database, no HTTP
  class.go                   Class: inventory | posture | health | event
  capability.go              CapabilityState + CapabilityManifest
  result.go                  Status + CollectorResult
  errsanitize.go             error classification and redaction
  collector.go               Collector interface, CollectorSet, RunAll
  section.go                 SectionSpec, Registry, reconciliation rules
  fingerprint.go             per-section hashing + metadata guard
  chunk.go                   batching for high-cardinality sections
  health.go                  DomainHealth, TelemetryHealth, HealthTracker
  envelope.go                wire envelope
  service.go                 cycle orchestration against interfaces

internal/service/telemetry/  wiring layer
  adapter.go                 SQLite stores -> domain interfaces
  service.go                 lifecycle, scheduler handler support

internal/store/
  telemetry_state.go         section state: hashes and timestamps ONLY
  telemetry_outbound.go      bounded durable send queue

internal/models/
  telemetry_event.go         TelemetryChangeEvent + priority
```

The domain package deliberately has no database or HTTP dependency, so cycle logic is testable without either — the same approach the software service takes with its `Catalog` interface.

---

## 2. Telemetry classes

Four classes are kept distinct all the way to the wire, so the backend can never mistake a health sample for an inventory snapshot.

| Class | Contents | Fingerprinted? |
|---|---|---|
| `inventory` | identity, hardware, OS, volumes, network, sessions, processes, persistence, certificates | Yes |
| `posture` | firewall, antivirus, encryption, Secure Boot, TPM, patch state | Yes |
| `health` | CPU/memory/disk utilisation, battery, uptime | **Never** |
| `event` | discrete state changes | n/a |

Health is excluded from fingerprinting by construction: a sample changes on every read, so hashing it would mark it permanently changed and defeat reconciliation. `Class.Fingerprinted()` encodes this, and `ShouldUpload` short-circuits health to always send.

---

## 3. Envelope

```go
type Envelope struct {
    SchemaVersion   int                `json:"schema_version"`
    AgentVersion    string             `json:"agent_version"`
    DeviceID        string             `json:"device_id"`
    CollectedAt     string             `json:"collected_at"`
    Platform        string             `json:"platform"`
    Class           Class              `json:"class"`
    FullSnapshot    bool               `json:"full_snapshot"`
    Sections        []string           `json:"sections"`
    SectionVersions map[string]int     `json:"section_versions,omitempty"`
    Capabilities    CapabilityManifest `json:"capabilities,omitempty"`
    Data            SectionData        `json:"data,omitempty"`
    Chunk           *ChunkMeta         `json:"chunk,omitempty"`
    Meta            *Meta              `json:"meta,omitempty"`
}
```

### `Sections` is a correctness requirement

Once sections upload independently, most messages carry only what changed. `Sections` declares which sections are present **and authoritative** in that message. The backend must **merge** them and leave the rest untouched.

**A backend that replaces wholesale would wipe every section that simply had nothing new to report.** This is the single hardest dependency in the whole design and it gates Phase C.

### Two levels of schema version

The global `schema_version` covers the envelope. `section_versions` gives each section its own version, so `storage` can reach v3 while `identity` stays v1 without a global bump. A section whose stored version differs from its current spec version uploads immediately, regardless of content hash, so the backend always sees the new shape.

---

## 4. Capability manifest

Five states, because four different reasons for "no data" lead to four different operator actions:

| State | Meaning | Action |
|---|---|---|
| `supported` | present and collected | none |
| `not_present` | hardware or feature genuinely absent — no TPM chip, no battery | none, ever |
| `unsupported` | present, but this driver/firmware/config will not expose it | possibly fixable |
| `disabled` | switched off by configuration | flip a flag |
| `unavailable_on_os` | this OS cannot provide it at all | none, ever |

`not_present` and `unsupported` are deliberately distinct: "this desktop has no battery" and "this laptop has a battery but the firmware reports nothing" are different facts.

Keys: `storage.smart`, `storage.encryption`, `patch_inventory`, `sessions`, `processes`, `processes.cmdline`, `battery_detail`, `tpm`, `secure_boot`, `certificates`, `directory_join`, `network.routing_table`, `persistence`, `peripherals.usb`.

A new manifest defaults every known key to `unavailable_on_os`, so a capability nobody claimed reports a defined state rather than silently vanishing. Invalid states are coerced rather than transmitted.

---

## 5. Collection status

```go
type CollectorResult struct {
    Collector, Section string
    Status             Status   // success|partial|unsupported|permission_denied|timeout|error
    CollectedAt        string
    DurationMS         int64
    Source             string   // "wmi:root/wmi:BatteryStaticData", "exec:smartctl"
    ItemCount          int
    Warnings           []string
    WarningsDropped    int
    Error              string   // reason code only — never raw output
}
```

`Status.Failed()` is true only for `error`, `permission_denied` and `timeout`. `unsupported` is explicitly **not** a failure, so a fleet of desktops without batteries does not accumulate failures forever.

### Error sanitization

Errors are **classified, never echoed**. Only a fixed vocabulary reaches the wire: `command_not_found`, `permission_denied`, `timeout`, `canceled`, `not_supported`, `not_found`, `parse_failed`, `empty_output`, `wmi_query_failed`, `exit_status:N`, `unexpected_error`.

This matters because `os/exec` errors can carry stderr verbatim, and command output routinely contains hostnames, usernames, absolute paths, connection strings and occasionally credentials. `exec.ExitError.Stderr` in particular would leak wholesale if `err.Error()` were transmitted.

Collectors wrap sentinel errors (`ErrNotSupported`, `ErrParseFailed`, `ErrEmptyOutput`, `ErrWMIQuery`) so classification is deterministic rather than dependent on matching error text.

Warnings are agent-authored but may still interpolate system values, so they get redaction and bounding: credential-shaped `key=value` pairs, long token-shaped runs, and Windows/Unix user home paths are replaced with placeholders; everything is stripped of control characters, bounded to 256 bytes on a rune boundary, and capped at ten per result with a dropped count.

---

## 6. Per-section reconciliation

This replaces the concept of a single global force-resend. **The legacy `agentInfoForceResend` is untouched**; these intervals govern the new layer's own sections.

```go
type SectionSpec struct {
    Name              string
    Class             Class
    SchemaVersion     int
    CollectInterval   time.Duration  // how often to gather
    ReconcileInterval time.Duration  // max gap between uploads when unchanged
    Chunked           bool
}
```

A section uploads when its **hash changed**, its **schema version changed**, it has **never been uploaded**, or its **reconcile interval elapsed**. Health always uploads.

| Section | Class | Collect | Reconcile | Chunked |
|---|---|---|---|---|
| `identity`, `firmware`, `tpm`, `cpu`, `memory_modules`, `physical_disks` | inventory | 6 h | 24 h | no |
| `os`, `volumes`, `network` | inventory | 1 h | 24 h | no |
| `sessions` | inventory | 15 min | 4 h | no |
| `persistence` | inventory | 1 h | 12 h | yes |
| `processes` | inventory | 15 min | 1 h | yes |
| `certificates` | inventory | 12 h | 24 h | yes |
| `security_posture`, `encryption`, `secure_boot` | posture | 15 min | 1 h | no |
| `patches` | posture | 6 h | 12 h | yes |
| `health` | health | 15 min | — | no |

A stable device now re-sends its serial number **once a day instead of 24 times**, while its firewall state still reconciles hourly.

`software` and `services` are absent from this table on purpose: they remain on the existing pipeline at its current cadence. A test asserts they are not registered here, so the boundary cannot erode by accident.

---

## 7. Change detection and the metadata guard

```go
type SectionData map[string]any        // section name -> payload
type SectionHashes map[string]string   // section name -> sha256

func Fingerprint(data SectionData) (SectionHashes, error)
func Changed(prev, cur SectionHashes) []string
```

Each section hashes independently, so a changed firewall state uploads without also re-sending unchanged CPU, RAM, disk and peripheral data.

**`Fingerprint` rejects envelope metadata outright.** Passing a `Meta`, `CollectorResult`, `TelemetryHealth` or `DomainHealth` into a section returns an error naming where metadata belongs.

This guard exists because it is the one failure mode that would silently disable the entire design: those types carry durations, timestamps and queue depths that differ every cycle, so a section containing one would hash differently forever, mark itself permanently changed, and quietly restore full-payload-every-cycle uploads. That is invisible on one endpoint and very expensive across a fleet, so it fails loudly instead.

Two further rules:

- **`Changed` ignores sections absent from the current cycle.** Absence means "not collected", not "deleted"; treating it as a change would re-upload stale data.
- **Collectors must sort list payloads.** `encoding/json` sorts map keys but preserves slice order, so a process list in OS-enumeration order produces a new hash every cycle. A test documents this.

---

## 8. Separated state and queue

Two distinct stores, because they have different sensitivities and different lifetimes.

**`telemetry_section_state`** holds hashes and timestamps and has **no payload column**. Change detection needs a hash and a few dates; keeping full inventory here would persist a device's complete hardware, network, user and security profile on disk indefinitely for no operational gain.

**`telemetry_outbound`** holds payloads only while in flight and deletes them on delivery. It is bounded along all three axes that can independently run away:

| Bound | Default |
|---|---|
| Age | 72 h |
| Rows | 5 000 |
| Total bytes | 64 MiB |

Eviction drops **dead-lettered rows first, then oldest lowest-priority**, so a burst of routine inventory can never push out an undelivered critical security event. Every eviction is counted and surfaced in telemetry health, so loss is never silent.

**Dead-letter state.** A message that exhausts its delivery attempts (5) is moved out of the delivery path rather than retried forever or deleted. This is not cosmetic: `GetPending` orders by `(priority, id)`, so permanently-rejected messages accumulate at the head of the queue — a full page of them would starve everything behind it and stall the device's telemetry indefinitely. Dead-lettered rows are excluded from `GetPending` and from queue depth, retained on disk for inspection, and reported separately in telemetry health.

Persisting section state across restarts is what makes an agent restart cheap. The legacy path keeps its hash in a package variable, so every restart re-uploads everything.

**Delivery, not enqueue, advances the reconcile clock.** The interval measures how long it has been since the *backend* saw a section, so a message sitting in the queue must not count.

---

## 9. Chunking, not truncation

```go
type ChunkMeta struct {
    SnapshotID string
    BatchIndex int
    BatchCount int
    TotalItems int
    Truncated  bool  // last resort only
}
```

A truncated process or certificate list is indistinguishable from a genuinely short one, so silently dropping the tail would misreport the endpoint. The ladder:

1. Split into batches of at most 900 KB.
2. If a single item exceeds the cap, drop its heaviest optional field for that item and flag it.
3. Only then set `Truncated: true`, with `ExcludedItems` counting the dropped items and `TotalItems` recording the real pre-exclusion count — always visible in telemetry health. `TotalItems - ExcludedItems` is the exact number the backend should expect to reassemble.

**Backend requirement:** the existing `"snapshot": "full"` replace-on-receipt semantics are wrong for batch 0 of N. The backend must buffer by `snapshot_id` and commit only when all `batch_count` batches arrive, discarding incomplete snapshots after a timeout. This gates the chunked domains in Phase E.

---

## 10. Telemetry health

```go
type DomainHealth struct {
    Domain, State         string  // healthy|partial|disabled|not_applicable|permission_denied|failing
    LastSuccessfulCollect string
    LastUpload            string
    ConsecutiveFailures   int
    LastError             string  // sanitized
}

type TelemetryHealth struct {
    Domains           []DomainHealth
    PendingQueueDepth int
    DroppedEventCount int64
    CollectorFailures int64
    LastFullSnapshot  string
}
```

Capability is consulted before status, so absent hardware reports `not_applicable` indefinitely rather than accumulating failures. This lets an operator read a device as:

```
Identity: Healthy   Storage: Healthy    Patches: Partial
Security: Healthy   Processes: Disabled Battery: Not Applicable
Certificates: Permission Denied
```

Health lives in the envelope's `Meta`, never inside a fingerprinted section.

---

## 11. Change events

`TelemetryChangeEvent` is a distinct model from `AuditLog`. An audit log is an OS record the agent forwarded; a change event is the agent's own assertion that a tracked property moved from one value to another. Collapsing them would turn "when was BitLocker disabled on this device" into a text search over log messages.

They may share transport without sharing a model.

```go
type TelemetryChangeEvent struct {
    EventID, EventType, Section string
    Priority      EventPriority
    Severity      string
    OccurredAt    string  // when it happened, where knowable
    DetectedAt    string  // when the agent noticed
    PreviousValue any
    CurrentValue  any
    SchemaVersion int
}
```

`OccurredAt` and `DetectedAt` are separate because poll-based detection can differ from the event by up to one collection interval; conflating them would misdate every change.

**Critical (immediate upload, bypassing the flush interval):** `firewall_disabled`, `antivirus_disabled`, `realtime_protection_disabled`, `encryption_disabled`, `new_local_admin`, `secure_boot_disabled`, `tamper_protection_disabled`.

**Normal (batched):** software installed/removed, service state changed, IP or hostname changed, USB connected, OS update installed, reboot required, peripheral changed.

Priority is decided in one place (`PriorityForEventType`) rather than at each call site.

---

## 12. Collector interface

```go
type Collector interface {
    Name() string
    Section() string
    SchemaVersion() int
    Capability(ctx context.Context, cfg CollectorConfig) (key string, state CapabilityState)
    Collect(ctx context.Context, cfg CollectorConfig) (payload any, result CollectorResult)
}
```

Every collector takes a context from day one. The legacy path cannot be cancelled — its 90-second timeout abandons the goroutine while spawned subprocesses keep running — and that debt must not grow.

`Capability` is called even when `Collect` is skipped, so the backend always learns *why* data is absent.

`RunAll` contains panics per collector: one malformed WMI response must not cost the cycle every other section. `CollectorConfig` is a narrow struct rather than `*config.Config`, keeping the domain decoupled and collectors trivially testable.

---

## 13. What to extend versus build new

| Need | Approach |
|---|---|
| SMART, volumes, battery detail | **New collectors** reading alongside existing disk/system code, not edits to it |
| Sessions, directory join, VM detection | New collectors — no existing equivalent |
| Patch inventory | New chunked domain; today's count-only view stays where it is |
| Certificates | New chunked domain — never embedded in an inventory struct |
| Processes, persistence | New chunked domains |
| Browser inventory | **Derive from existing software inventory** — a classification pass, not a collector |
| Device health | New `health` section reusing metrics `osinfo.Collect()` already gathers and discards |
| Change events | New model; reuse the durable-queue *pattern*, leave `internal/logging/` untouched |
| Software, services | **Unchanged.** Existing pipeline |

---

## 14. Configuration

```go
TelemetryEnabled         bool     `json:"telemetry_enabled"`          // default false
TelemetryCollectInterval Duration `json:"telemetry_collect_interval"` // default 15m
TelemetryQueueMaxRows    int      `json:"telemetry_queue_max_rows"`   // default 5000
TelemetryQueueMaxBytes   int64    `json:"telemetry_queue_max_bytes"`  // default 64MiB
TelemetryQueueMaxAge     Duration `json:"telemetry_queue_max_age"`    // default 72h

ProcessesCollectCmdline      bool `json:"processes_collect_cmdline"`      // default false
IncludeBuiltinScheduledTasks bool `json:"include_builtin_scheduled_tasks"` // default false
CollectRoutingTable          bool `json:"collect_routing_table"`          // default false
```

`telemetry_enabled` defaults to **false**, so adding the layer to an existing fleet is a no-op until an operator opts in and the backend contract exists. When disabled, `buildTelemetryTask` returns nil and the store files are never created.

Defaults work through the existing mechanism: `Load()` seeds the struct, then unmarshals the file over it, so an absent key keeps the default and an explicit `false` is honoured. This is why these fields are plain `bool` rather than `*bool` — a test pins the behaviour.

Getters floor zero and negative values, so a malformed config cannot produce a hot loop or an unbounded queue.
