# Enterprise Telemetry

Analysis, architecture and roadmap for expanding SentinelGo into a full enterprise endpoint inventory and posture agent, comparable to Intune, Workspace ONE, Ivanti, Endpoint Central and Jamf.

**DLP is out of scope for this work.** The architecture only avoids foreclosing a future native DLP component.

## Documents

| Document | Contents |
|---|---|
| [01-current-inventory.md](01-current-inventory.md) | What the agent collects today, by what mechanism, how often, and whether it reaches the backend |
| [02-gap-analysis.md](02-gap-analysis.md) | Gaps against enterprise expectations, plus a per-OS support matrix that says explicitly where an OS cannot supply a value |
| [03-collection-matrix.md](03-collection-matrix.md) | The recommended collection mechanism for every missing data category, on each platform |
| [04-architecture.md](04-architecture.md) | The telemetry layer: envelope, capabilities, collection status, per-section reconciliation, state and queue separation, chunking, health, change events |
| [05-impact-and-roadmap.md](05-impact-and-roadmap.md) | Performance and bandwidth impact, fleet scalability at 10k endpoints, privacy and security analysis, backend compatibility, phased roadmap |
| [06-existing-code-observations.md](06-existing-code-observations.md) | Issues found in existing code. **Findings only — each needs approval before the subsystem is touched** |
| [07-phase-g-change-events.md](07-phase-g-change-events.md) | Phase G as built: watched values, the events emitted and the ones deliberately blocked, debounce/cooldown/flapping, event identity, delivery routing and privacy guarantees |
| [08-platform-validation.md](08-platform-validation.md) | The exact `-telemetry-cycle` validation procedure for real Linux and macOS hardware, and what is expected per section |
| [09-remaining-gaps-design.md](09-remaining-gaps-design.md) | Design-only recommendations for the six enterprise gaps still open, with a build/defer call on each |
| [../backend/telemetry-contracts.md](../backend/telemetry-contracts.md) | Backend specification for the Supabase owners: RPCs, payload shapes, merge and chunk-assembly semantics, reference DDL |
| [../backend/backend-compatibility-checklist.md](../backend/backend-compatibility-checklist.md) | Point-by-point compatibility checklist for the SentinelOps backend, marking each item required vs optional |

## Governing constraint

The existing scheduler, collectors, local stores, transport, authentication, software/services pipelines and audit-logging pipeline are **stable foundations and are not modified**. The telemetry layer is built around them, reusing existing code by calling it read-only and registering a single scheduler task through the same public path `services-collect` uses.

Anything worth changing in existing code is recorded in document 06 and requires approval first.

## Status

| Phase | Contents | State |
|---|---|---|
| A | Analysis documents, backend contract, `CLAUDE.md` correction | **Complete** |
| B | Telemetry foundation in `internal/telemetry/` | **Complete** |
| C | P0 — identity, VM detection, directory join, sessions, OS, physical disks + SMART, volumes, network | **Code complete** |
| D | P1 — per-volume encryption detail, patch inventory, password policy, privileged accounts | **Code complete** |
| E | P2 — processes, certificates, persistence, routing table (chunked) | **Code complete** |
| F | P3 — battery detail, device health | **Code complete** |
| G | P4 — change events with priority | **Code complete** |

"Code complete" means: implemented, unit- and parser-tested, cross-compiled for
every target, and registered in `collectors.RegisterAll`. It does **not** mean
validated. Two things are still outstanding for every phase from C onward:

- **Backend.** `agent_enqueue_telemetry` and `agent_enqueue_telemetry_events`
  live in the separate SentinelOps backend repository. Until they exist and
  implement section-**merge** semantics and chunk assembly, telemetry must stay
  disabled — a missing RPC answers 404, which the sender records as a rejection
  and dead-letters after five attempts rather than delivering. See
  [../backend/backend-compatibility-checklist.md](../backend/backend-compatibility-checklist.md).
- **Real hardware.** Collector code has been compile-tested on all targets and
  its parsers are unit-tested against captured command output, but the
  `_linux.go` and `_darwin.go` command paths have **never been executed on a
  real Linux or macOS machine**. See
  [08-platform-validation.md](08-platform-validation.md) for the validation
  procedure.

Secure Boot, TPM and Endpoint Protection collectors were added after Phase G,
closing capability keys that had been reporting a manifest default rather than a
real answer.

## Current behaviour

The telemetry layer is wired but **disabled by default** (`telemetry_enabled: false`). With it off, `buildTelemetryTask` returns nil, no store files are created, and the agent's wire behaviour is unchanged.

Change events have a second, independent gate (`telemetry_events_enabled: false`), which is a nil `*telemetry.EventEngine` on the cycle service rather than a flag tested in many places.

Enabling telemetry now runs **22 registered collectors** filling **22 declared sections**, and produces real traffic. Three of those sections — `firmware`, `cpu` and `memory_modules` — are sourced from the legacy `osinfo` inventory through the bridge collectors rather than a second hardware implementation, and `routes` is additionally gated behind `collect_routing_table`.

Because enabling it produces traffic, it must not be enabled against production before the backend RPCs exist; see the Status note above.
