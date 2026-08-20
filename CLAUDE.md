# SentinelGo

Cross-platform Go endpoint agent. Collects OS-level inventory and security telemetry (CPU, memory, disk, network, battery, encryption, security posture, software, services, event logs) and reports it to a Supabase backend through periodic scheduler tasks. Runs as a native service on Linux (systemd), macOS (launchd), and Windows (Service API). Self-updates from Supabase Storage, verified by SHA-256 checksum and ed25519 signature.

## Build & Test

```bash
make build                        # dev build -> bin/sentinelgo
make test                         # go test ./...
make quality-check                # go vet + golangci-lint
make format-check                 # gofmt check
make pre-release                  # quality gate + build
make release VERSION=vX.Y.Z      # cross-compile all platforms
make check-no-cgo                 # fail if any `import "C"` exists
make verify-cross                 # type-check every target with CGO_ENABLED=0
```

All builds use `CGO_ENABLED=0`. Version is injected via `-ldflags` from git tags.

## Architecture

```
cmd/
  sentinelgo/          the only entrypoint: CLI, service lifecycle

internal/
  main_integration.go  startup sequencing, task wiring, shutdown ordering
  scheduler/           task registry and periodic runner (all loops live here)
  config/              JSON config loading and credential storage (no env vars)
  lockfile/            file-based process locking and PID tracking
  osinfo/              inventory collectors, one sub-package per domain
    shared/            SystemInfo types + RunCommand/ReadFileContent helpers
  service/
    agent/             inventory upload   -> agent_enqueue_inventory
    software/          software inventory -> agent_enqueue_software
    services/          service inventory  -> agent_enqueue_services
    auditlog/          audit log upload   -> agent_enqueue_audit_logs
    auth/              agent-login, JWT refresh, circuit breaker
    task/              remote task execution
    telemetry/         telemetry layer wiring (stores, scheduler task)
    rpcutil/           shared enqueue retry policy and response types
  telemetry/           enterprise telemetry domain layer (no DB, no HTTP)
  auditlogs/collector/ OS event log collection (per-platform)
  logging/             collector -> parser -> SQLite queue -> uploader
  store/               local SQLite (software, services, audit logs, tasks, telemetry)
  taskstore/           remote task client and local task DB
  updater/             release check via RPC, download, verify, atomic replace, restart
  models/              shared data models

docs/telemetry/        telemetry analysis, architecture, roadmap
docs/backend/          backend contract specifications
scripts/               Release, diagnostics, and pre-release checks
release/               Compiled binaries (never edit directly)
```

**The backend is not in this repository.** It is a Supabase project reached over
HTTP: one edge function (`agent-login`) and a set of `agent_enqueue_*` /
`agent_*` Postgres RPCs. There are no edge functions, SQL files or migrations
here — proposed backend changes are specified as markdown in `docs/backend/`.

## Runtime Flow

1. Load config -> acquire lockfile -> validate -> init auth
2. Authenticate via the `agent-login` edge function -> store JWT (refreshed every 1m)
3. Register scheduled tasks, then run them on independent tickers with startup jitter:
   - `agent-info-update` (5m)  -> collect osinfo, upload if the fingerprint changed
   - `software-sync` (5m)      -> collect software, upload if changed
   - `services-collect` (5m)   -> collect services, upload if changed
   - `telemetry-collect` (15m) -> telemetry layer; disabled by default
   - `auto-update` (1h)        -> check for a newer release
   - audit-log collect + upload (5m), and task poll + execute (5m)
4. Update: `get_latest_agent_release` RPC -> download from Supabase Storage ->
   verify SHA-256 and ed25519 signature -> stop -> replace binary -> restart

There is no single heartbeat loop. Each task is self-sufficient and fails
independently; every handler is wrapped in `recover()` by the scheduler.

## Key Conventions

- Go module: `sentinelgo`, requires Go 1.25+
- Standard Go layout: `cmd/` for entrypoints, `internal/` for private packages
- Config format is JSON only (not YAML, not TOML)
- Config paths: `/opt/sentinelgo/.sentinelgo/config.json` (Linux/macOS), `C:\sentinelgo\.sentinelgo\config.json` (Windows)
- Never hardcode Supabase credentials or API keys
- Never modify `release/` directory directly; use `make release`
- New enterprise telemetry goes through `internal/telemetry/` (additive layer);
  see `docs/telemetry/04-architecture.md`. The existing inventory, software,
  services and audit-log pipelines are stable foundations — extend around them
  rather than modifying them, and see `docs/telemetry/06-existing-code-observations.md`
  for known issues in existing code that need approval before being touched
- Service lifecycle managed by `github.com/kardianos/service`
- System metrics collected via `github.com/shirou/gopsutil/v4`
- Most telemetry is shell-out based, funnelled through `shared.RunCommand` /
  `shared.RunCommandOutput` (30s timeout, NUL stripping). Native WMI via
  `github.com/yusufpapurcu/wmi` is preferred for new Windows collectors; see
  `internal/osinfo/display/display_windows.go` for the pattern
- Backend calls use `rpcutil.WithEnqueueRetry`, which **drops non-401 4xx
  responses**. Log payload size on every send, or an oversized payload fails
  permanently and silently

## Rules

- Always build with `CGO_ENABLED=0` for cross-compilation
- **Never add `import "C"` (no cgo).** The agent must stay a static, dependency-free binary that cross-compiles from one host to all platforms. cgo breaks all three: it needs a per-target C toolchain, links dynamically against system libs, and can't cross-compile (e.g. you can't build a macOS binary from Linux). If a feature seems to need a native library, use a subprocess to the OS's CLI or a pure-Go equivalent instead. Example: the audit log collectors read logs via `journalctl -o json` (Linux) and `log show --style ndjson` (macOS) rather than `libsystemd`/`OSLog`.
- **Why this is a hard rule, not a preference:** under `CGO_ENABLED=0` a cgo file's build constraint silently becomes false, so the file is *excluded* and any fallback (e.g. a stub collector) compiles in its place. The result is missing functionality at runtime, not a build error — exactly the kind of failure that hides for a long time. `make check-no-cgo` enforces this in the pre-release gate.
- Validate platform-specific code on all targets with `make verify-cross` (compiles every `GOOS/GOARCH` with `CGO_ENABLED=0`). Build tags / `_linux.go`/`_darwin.go`/`_windows.go` suffixes mean a file is only compiled on its OS, so a Windows-only dev never type-checks the Linux file otherwise.
- Be careful with signal handling, startup order, and graceful shutdown (runs as system service)
- Keep error handling explicit; this is a long-running service
- Auth tokens auto-refresh; never assume a token is permanently valid

## Cross-Platform Considerations

- `internal/osinfo/` contains platform-specific files (build tags or `_linux.go`, `_darwin.go`, `_windows.go` suffixes)
- Any change to osinfo or service packages must be mentally validated against all three platforms
- File paths, permissions, and service management differ per OS
- Test with `GOOS=linux`, `GOOS=darwin`, `GOOS=windows` to catch compilation issues
- The updater must handle binary replacement atomically on all platforms
