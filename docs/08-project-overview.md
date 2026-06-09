# SentinelGo — Project Overview

> Canonical architecture reference. Merges and supersedes the older `docs/09-system-architecture.md`, `EXECUTION_FLOW.md`, and `process_flow.md`.

## 1. What SentinelGo is

A cross-platform Go system agent that:

- Collects OS-level metrics (CPU, memory, disk, network, battery, encryption status, peripherals, security state) and reports them as a periodic **heartbeat** to a Supabase backend.
- Maintains a **software inventory** (installed apps + versions) and reconciles it on every sync via the local SQLite store and the Supabase `agent-software` Edge Function.
- Streams **audit log** events (Windows Event Log, Linux journald, macOS unified log) to a Supabase Edge Function, with a durable local SQLite queue and exponential-backoff retry.
- Polls a **task queue** for ad-hoc commands, downloads the script payload from a private `command-scripts` Storage bucket (RLS-gated), executes it, and reports the outcome back.
- Refreshes its own binary from **GitHub Releases** with an atomic on-disk replace.
- Runs as a native system service (systemd / launchd / Windows Service) or in foreground mode for debugging.

## 2. Repository layout

```
sentinelgo/
├── cmd/
│   └── sentinelgo/                  CLI entry point. Parses flags, dispatches subcommands,
│                                   installs/uninstalls the service, then hands off to
│                                   the kardianos service interface.
│
├── internal/
│   ├── main_integration.go         MainIntegration: orchestrates auth, scheduler,
│   │                               logging, task manager, and updater in the order
│   │                               documented in §4.
│   │
│   ├── auth/                       EnhancedAuth: JWT login, circuit breaker, auto-refresh.
│   ├── config/                     JSON config loading, env-var overrides, validation,
│   │                               keychain/credential-storage helpers.
│   ├── lockfile/                   File-based process lock keyed on agent UUID + version.
│   ├── osinfo/                     Cross-platform hardware metrics. Files split by
│   │                               build tag (_linux.go, _darwin.go, _windows.go) and
│   │                               by subsystem (cpu/, ram/, disk/, network/, ...).
│   ├── procinfo/                   Process discovery and per-process metadata.
│   ├── scheduler/                  Cron-style task scheduler that drives the heartbeat,
│   │                               software sync, agent-info refresh, and updater.
│   │
│   ├── service/
│   │   ├── agent/                  Agent-info upload service.
│   │   ├── auth/                   Login + token-rotation service.
│   │   └── task/                   Task poller + script executor + result reporter.
│   │
│   ├── logging/                    Local queue, batching, durable checkpoint, HTTPS upload
│   │                               to the audit-log Edge Function.
│   ├── auditlogs/
│   │   ├── collector/              Per-OS collectors (Windows Event Log, journalctl,
│   │   │                           log show), shared parse/exec helpers, no-op stub.
│   │   └── parser/                 Log normalization and severity mapping.
│   ├── auditlogstore/              SQLite-backed durable queue for audit events.
│   │
│   ├── updater/                    GitHub Releases check, asset download, atomic
│   │                               binary replace, restart orchestration.
│   ├── store/                      SQLite store: software inventory + pending sync state.
│   ├── taskstore/                  SQLite store: assigned tasks + status transitions.
│   │
│   ├── network/                    Connectivity probing, IP/interface discovery.
│   ├── sanitize/                   PII / sensitive-value redaction before upload.
│   ├── httpx/                      Shared HTTP client with retry/timeout.
│   ├── models/                     Shared data types.
│
├── supabase/                       TypeScript Edge Functions (deployed to Supabase).
├── scripts/                        Release, diagnostics, pre-release checks.
├── installation-doc/               OS-specific install scripts and INSTALLATION.md.
├── docs/                           This directory.
├── Makefile                        Build, test, cross-compile, pre-release gate.
└── go.mod                          Module path: `sentinelgo`; requires Go 1.25+.
```

## 3. High-level architecture

```
+----------------------------------------------------------------------------+
|                       SentinelGo Agent Process                              |
|                                                                              |
|  +-----------+  +-----------+  +-----------+  +-----------------------+    |
|  |  cmd/     |  |  main_    |  | scheduler/|  |  kardianos/           |    |
|  | sentinelgo|->|integration|->| cron loop |  |  service iface        |    |
|  +-----------+  +-----+-----+  +-----+-----+  +-----------+-----------+    |
|                       |              |                      |               |
|                       v              v                      v               |
|  +----------+   +----------+  +-----------+   +-------------------------+  |
|  | config/  |   |  auth/   |  |  service/ |   |  service manager        |  |
|  |  loader  |   |  login + |  |  |- agent/ |   |  (systemd / launchd /   |  |
|  +----------+   |  refresh |  |  |- auth/  |   |   Windows SCM)          |  |
|                 +----------+  |  +- task/  |   +-------------------------+  |
|                                +-----+-----+                                |
|                                      |                                      |
|  +-----------+  +-----------+  +-----v----+  +-----------------------+     |
|  |  osinfo/  |  | procinfo/ |  | software |  |  audit-logs           |     |
|  |  hardware |  | processes |  | inventory|  |  collector ->         |     |
|  |  metrics  |  |           |  | (store/) |  |  auditlogstore ->     |     |
|  +-----------+  +-----------+  +-----------+  |  logging uploader     |     |
|                                                +-----------+-----------+     |
|                                                            |                 |
|  +---------------+  +---------------+                       |                 |
|  |  lockfile/    |  |  updater/     |                       |                 |
|  |  single inst. |  |  GitHub rel.  |                       |                 |
|  +---------------+  +---------------+                       |                 |
+----------------------------------------------------------------------------+
                                                             |
                                                             v
                                              +------------------------------+
                                              |  Supabase + Edge Functions   |
                                              |  GitHub Releases             |
                                              |  Platform Event Logs         |
                                              +------------------------------+
```

## 4. Runtime flow (the contract `MainIntegration.Start` implements)

1. **Load config** from `--config` path (or default), validate it (`config.ValidateConfiguration`).
2. **Startup update check** — best-effort, async; if a newer release is available, hand off to the updater.
3. **Initialize auth** — `auth.EnhancedAuth` logs the agent in, stores the JWT, schedules preemptive refresh.
4. **Configure scheduled tasks** — heartbeat, software sync, agent-info refresh, updater check.
5. **Start logging (audit) service** if enabled in config; otherwise skip.
6. **Start task manager** (polling + execution) if enabled.
7. **Start scheduler loop** — drives the configured cron entries.
8. **Block** on the service's `Stop()` channel for graceful shutdown; on signal, drain queues, stop collectors, close DBs, exit.

Concrete startup ordering lives in `internal/main_integration.go::Start`. Each numbered step is its own method so it's individually testable.

## 5. Configuration

Single JSON file. Default locations:

- Linux / macOS: `/opt/sentinelgo/.sentinelgo/config.json`
- Windows: `C:\sentinelgo\.sentinelgo\config.json`

Env-var overrides use the form `SENTINELGO_<FIELD>` (see `docs/02-config-module.md`). The file is the source of truth; env vars are an install-time convenience.

## 6. Build and test

```bash
make build                # dev build -> bin/sentinelgo[.exe]
make test                 # go test ./...
make verify-cross         # type-check every GOOS/GOARCH with CGO_ENABLED=0
make check-no-cgo         # fail if any `import "C"` is reintroduced
make pre-release          # quality gate + build
make release VERSION=vX.Y.Z
```

All builds use `CGO_ENABLED=0`. The build is static and cross-compiles from one host to all release targets.

## 7. Operational concerns

- **Single instance** — `internal/lockfile` keys the lock on the agent UUID + binary version, so an in-place upgrade can replace the running binary cleanly.
- **At-least-once uploads** — both audit logs and task results are stored in SQLite before upload; a crash mid-upload replays from the checkpoint.
- **Auth** — JWT is auto-refreshed; the agent never assumes a token is permanently valid (see `internal/auth/circuit_breaker.go`).
- **Updates** — see `docs/07-updater-module.md` for the atomic-replace protocol and the GitHub Releases check cadence.
- **Cross-platform** — every change to `osinfo/`, `auditlogs/collector/`, or `service/` must be validated on all three OSes via `make verify-cross`; build tags mean the Linux file is otherwise invisible to a Windows-only dev.
