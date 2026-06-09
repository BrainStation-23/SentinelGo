# SentinelGo

Cross-platform Go system monitoring agent. Collects OS-level metrics (CPU, memory, disk, network, battery, encryption status) and reports to a Supabase backend via heartbeat loop. Runs as a native service on Linux (systemd), macOS (launchd), and Windows (Service API). Includes automatic self-update from GitHub Releases.

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
  sentinelgo/          main agent: service lifecycle, CLI, heartbeat loop, updater
  auditlogs/           audit log collection service

internal/
  config/              JSON config loading, env vars, credential storage
  heartbeat/           payload generation and Supabase API calls
  lockfile/            file-based process locking and PID tracking
  osinfo/              cross-platform hardware metrics (platform-specific files)
  service/             JWT auth (authService.go), agent info (agentService.go)
  updater/             GitHub release check, binary download, atomic replace, restart
  auditlogs/           audit log collection and forwarding
  logging/             logging utilities
  models/              shared data models
  constants/           shared constants

supabase/              Edge functions (TypeScript)
scripts/               Release, diagnostics, and pre-release checks
release/               Compiled binaries (never edit directly)
```

## Runtime Flow

1. Load config -> acquire lockfile -> init services
2. Authenticate via Supabase edge function (agent-login) -> store JWT
3. Collect osinfo -> send heartbeat -> sleep (default 5m) -> repeat
4. Daily GitHub release check -> download -> stop -> replace binary -> restart

## Key Conventions

- Go module: `sentinelgo`, requires Go 1.25+
- Standard Go layout: `cmd/` for entrypoints, `internal/` for private packages
- Config format is JSON only (not YAML, not TOML)
- Config paths: `/opt/sentinelgo/.sentinelgo/config.json` (Linux/macOS), `C:\sentinelgo\.sentinelgo\config.json` (Windows)
- Never hardcode Supabase credentials or API keys
- Never modify `release/` directory directly; use `make release`
- Service lifecycle managed by `github.com/kardianos/service`
- System metrics collected via `github.com/shirou/gopsutil/v3`

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
