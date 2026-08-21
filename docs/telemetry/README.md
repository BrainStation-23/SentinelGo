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
| [../backend/telemetry-contracts.md](../backend/telemetry-contracts.md) | Backend specification for the Supabase owners: RPCs, payload shapes, merge and chunk-assembly semantics, reference DDL |

## Governing constraint

The existing scheduler, collectors, local stores, transport, authentication, software/services pipelines and audit-logging pipeline are **stable foundations and are not modified**. The telemetry layer is built around them, reusing existing code by calling it read-only and registering a single scheduler task through the same public path `services-collect` uses.

Anything worth changing in existing code is recorded in document 06 and requires approval first.

## Status

| Phase | Contents | State |
|---|---|---|
| A | Analysis documents, backend contract, `CLAUDE.md` correction | **Complete** |
| B | Telemetry foundation in `internal/telemetry/` | **Complete** |
| C | P0 — identity, directory join, sessions, OS, volumes, SMART, network | Not started |
| D | P1 — encryption detail, patch inventory, policy, privileged accounts | Not started |
| E | P2 — processes, certificates, persistence, detailed network (chunked) | Not started |
| F | P3 — battery detail, device health | Not started |
| G | P4 — change events with priority | Not started |

Phase C is gated on a review of the A/B implementation and on the backend supporting section-merge semantics.

## Current behaviour

The telemetry layer is wired but **disabled by default** (`telemetry_enabled: false`). With it off, `buildTelemetryTask` returns nil, no store files are created, and the agent's wire behaviour is unchanged. No collectors are registered yet, so enabling it produces no sections and no traffic — which is the correct behaviour for "the foundation exists, the collectors do not".
