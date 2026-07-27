# Audit Remediation Summary

Implementation of all feasible agent-side findings from `AUDIT_REPORT.md`.
All changes verified: `go build` clean on linux/amd64, darwin/arm64, windows/amd64;
`go vet` clean on all three; affected package tests pass in `-short` mode.

No commits or pushes were made. No SentinelOps frontend, backend, Supabase, or
database repositories were modified.

---

## Phase 1 — Critical & High (Immediate)

### CRIT-02 — Unbounded enqueue retry loop
**File:** `internal/service/rpcutil/enqueue_retry.go`

`WithEnqueueRetry` previously looped forever on 5xx/network errors, able to
exhaust memory or hold a goroutine indefinitely on a pathological backend.
Added `maxEnqueueAttempts = 10` constant; the loop is now bounded. After 10
attempts the function returns an error so the caller can surface the failure
and the scheduler can record it.

### HIGH-01 — Foreground/service lock name inconsistency
**File:** `cmd/sentinelgo/service/lifecycle.go`

`RunForeground` used a version-qualified lock name (`sentinelgo-<version>`)
while the service mode used the fixed name `sentinelgo`. This meant two
different agent versions could run simultaneously without either detecting
the other. Changed to the fixed name `sentinelgo` in both modes.

### HIGH-05 — No systemd restart limit
**File:** `cmd/sentinelgo/service/svc_linux.go`

Added `StartLimitIntervalSec=120` and `StartLimitBurst=5` to the generated
systemd unit. Without these, a crash-looping agent was restarted indefinitely
by systemd, which could mask a real failure and hammer the Supabase endpoint.

### HIGH-06 — osinfo.Collect() loading config on every call
**File:** `internal/osinfo/collect.go` + all callers

Removed the internal `config.Load("")` call from `Collect()`. The function
now takes an explicit `agentVersion string` parameter. Callers pass
`cfg.CurrentVersion` (scheduler, commands, sync_inventory) or
`config.Version` (debug/dump CLI paths where no config is loaded). This
removes a file I/O side effect from a pure collection function and eliminates
a race between the collector and config writes.

Updated callers:
- `internal/scheduler/scheduler.go`
- `internal/service/task/native/sync_inventory.go` (+ test stubs)
- `cmd/sentinelgo/cli/debug.go`
- `cmd/sentinelgo/cli/commands.go`
- `internal/osinfo/collect_helper_test.go`

---

## Phase 2 — Security & Dead Code

### HIGH-02 — GetAgentInfo SELECT * with no row filter
**File:** `internal/service/agent/agent.go`

`GetAgentInfo` previously issued `SELECT *` with no WHERE clause, returning
all columns from potentially multiple rows. Changed to select only the seven
display columns and added `.Eq("device_id", cfg.DeviceID)` so the query is
scoped to the calling agent's own row (defence-in-depth on top of RLS).

### MED-11 — EPM AppPath not validated before use
**File:** `internal/epm/pipe_windows.go`

Added `validateAppPath()` called at the top of `evaluateAndLaunch()` before
any expensive OS work. It rejects:
- Empty paths
- UNC paths (`\\server\share` or `\\?\UNC\...`) — could resolve to an
  attacker-controlled network share
- Relative paths — ambiguous in an elevated context

### MED-01 — Dead `internal/auth` package
**Deleted:** `internal/auth/auth_logger.go`, `internal/auth/auth_logger_test.go`

`AuthLogger` was never imported by any production code. Removed entirely.

### MED-02 — Dead `AutoUpdateChecker` function
**File:** `internal/updater/checker.go`

`AutoUpdateChecker` (background hourly ticker) was never called; the scheduler
handles update checks via `handleAutoUpdate`. Removed the function and its
tests from `checker_test.go`, `updater_comprehensive_test.go`, and
`updater_test.go`.

### MED-03 — Dead `SessionManager`
**Deleted:** `internal/service/auth/session.go`, `internal/service/auth/session_test.go`

`SessionManager` wrapped `Service` but was never wired into production —
`MainIntegration` calls `authsvc.Service` directly. Removed entirely.

### MED-04 — Dead `Config.SecureConfigFile()` method
**File:** `internal/config/config.go`

`SecureConfigFile()` was a thin alias for `os.Chmod(c.Path, 0600)` that
was never called externally. The same hardening is already applied by
`SaveAtomic` via the unexported `secureConfigFile`. Removed the exported
method and its two tests.

### MED-05 — Dead `CheckAgentTaskPolling` no-op
**File:** `internal/logging/logging.go`

`CheckAgentTaskPolling` was a placeholder that only returned nil. Removed the
method and its test.

### MED-06 — Local `min()` shadows Go 1.21 builtin
**File:** `internal/store/tasks.go`

Removed the local `min(a, b int) int` definition. The project targets Go 1.25;
the builtin `min` is already available. The existing tests in `helpers_test.go`
now implicitly test the builtin.

### DB-2 — No periodic task-store pruning
**Files:** `internal/main_integration.go`, `internal/service/task/manager.go`

Added a `task-db-cleanup` scheduled task that runs weekly and calls
`TaskManager.CleanupCompletedTasks(cutoff)` where `cutoff = now - 7 days`.
Without this, completed task rows accumulated indefinitely in the local SQLite
queue on long-running agents. Added a `CleanupCompletedTasks` method to
`TaskManager` that delegates to the existing
`TaskPollingService.CleanupCompletedTasks`.

---

## Phase 3 — Structural, Code Quality, CI/CD, Cleanup

### MED-08 — Hardcoded macOS binary path in HandleInstall
**File:** `cmd/sentinelgo/service/lifecycle.go`

Replaced `const binaryPath = "/opt/sentinelgo/sentinelgo"` with
`os.Executable()` so installs in non-standard locations and development builds
work correctly on macOS.

### HIGH-04 — No warning when EPM enabled on non-Windows
**File:** `internal/main_integration.go`

Added an explicit `log.Printf` warning when `svc.Start()` fails on non-Windows.
The stub in `internal/epm/service_other.go` returns an informative error, and
the new log line at the call site makes it visible in the service log that EPM
was requested but is not supported on the current platform.

### LOW-02 — Unconditional noisy startup message
**File:** `cmd/sentinelgo/main.go`

Removed the unconditional `"Consider running './sentinelgo -stop' to stop old
versions first"` print that appeared on every non-install/uninstall invocation,
including running as a managed service where it was noise in the system log.

### LOW-06 — Unused config load in services.go
**File:** `cmd/sentinelgo/cli/services.go`

`HandleServicesListCommand` loaded config but used neither the result nor any
config field — the service list is collected from the OS directly. Removed the
`config.Load` call, the error log, and changed the unused `cfgPath` parameter
to `_`.

### LOW-08 — AI notes failure silent in CI
**File:** `.github/workflows/release.yml`

Added `echo "::warning::AI release notes generation failed..."` to the else
branch so GitHub Actions surfaces a yellow warning annotation on the release
workflow run when the AI notes step returns empty, instead of silently falling
back with no indication.

### LOW-01 — Windows update batch script self-delete uses var path
**File:** `internal/updater/installer.go`

Changed `del "%s"` (which interpolated the `bat` variable path at Go
format-string time) to `del "%%~f0"` (which resolves the running script's
own path at batch execution time). This is both safer and more idiomatic — the
script now reliably deletes itself regardless of how it was launched.

### MED-09 — Kill error gives no actionable guidance
**File:** `cmd/sentinelgo/cli/process.go`

Added a follow-up hint message when `kill` returns exit status 1 on
Linux/macOS: `"Hint: Process %d may be owned by a different user; try running
with elevated privileges (sudo)"`. This turns a cryptic failure into an
actionable instruction.

---

## Phase 4 — Documentation

### HIGH-07 — Goroutine lifetime undocumented in rpcutil
**File:** `internal/service/rpcutil/rpcutil.go`

Added doc comment section explaining that the spawned goroutine lives until
`fn` returns even after context cancellation, why that is acceptable (the
call is in-flight and cannot be cancelled mid-request), and that the goroutine
is cheap relative to the RPC it is executing.

### HIGH-03 — String-matching rationale undocumented in httperr
**File:** `internal/service/auth/httperr.go`

Added doc comment to `IsUnauthorized` explaining why string matching is used
instead of typed errors: the three client layers (postgrest-go SDK, hand-rolled
HTTP client, gotrue) each surface auth failures as differently shaped strings
with no shared error type, and centralising the heuristics here avoids
duplicating that knowledge across all call sites.

---

## Repository Hygiene

### .gitignore
Added patterns that were missing:
- `/sentinelgo`, `/sentinelgo.exe`, `/sentinelgo-epm`, `/sentinelgo-epm.exe`
  — root-level compiled binaries from accidental `go build .`
- `*.sqlite`, `*.sqlite-wal`, `*.sqlite-shm` — SQLite runtime files
- `/coverage`, `dev/`, `test-run/` — runtime test artifacts

### settings.json → .vscode/settings.json
Moved the VS Code editor settings file from the repo root to the conventional
`.vscode/` location so it is unambiguously identified as an IDE config file.

### internal-only → internal-only.md
Renamed the plain text notes file and added a markdown header so it is
clearly identified as a documentation file for maintainers.

### CLAUDE.md
Updated the Architecture, Runtime Flow, and Key Conventions sections to
reflect the current codebase: correct package layout, new scheduled tasks
(task-db-cleanup, services-collect, epm-policy-sync), EPM, and the two
invariants introduced in this remediation (`sentinelgo` lock name,
`osinfo.Collect(agentVersion)` signature).

---

## Deferred Items (require larger changes or backend coordination)

| ID | Reason deferred |
|----|-----------------|
| R-24 (HIGH-04 full) | Full Unix EPM socket transport — new feature, Phase 4 |
| R-25 | Structured logging migration — cross-cutting, Phase 4 |
| R-26 | postgrest-go replacement — upstream dependency |
| R-27 | Agent script hash verification — requires backend signing infrastructure |

---

## Verification

```
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build ./...  ✓
GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build ./...  ✓
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...  ✓

GOOS=linux   go vet ./...  ✓
GOOS=darwin  go vet ./...  ✓
GOOS=windows go vet ./...  ✓

go test -short ./internal/service/rpcutil ./internal/service/auth
        ./internal/store ./internal/config ./internal/logging
        ./internal/service/task/native ./internal/scheduler
        ./internal/updater  ✓  (all PASS)
```
