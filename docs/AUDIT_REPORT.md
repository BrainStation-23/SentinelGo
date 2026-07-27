# SentinelGo — Comprehensive Codebase Audit Report

**Project:** SentinelGo  
**Audit Date:** July 27, 2026  
**Auditor:** Kiro AI  
**Scope:** Full codebase — agent, infrastructure, CI/CD, security, performance, cross-platform compatibility  
**Go Version:** 1.25.11  
**Codebase Type:** Cross-platform Go agent (no frontend; Supabase is the backend)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Critical Issues — Immediate Attention Required](#2-critical-issues)
3. [High Priority Findings](#3-high-priority-findings)
4. [Medium Priority Findings](#4-medium-priority-findings)
5. [Low Priority Findings](#5-low-priority-findings)
6. [Code Quality Assessment](#6-code-quality-assessment)
7. [Dead and Unused Code Report](#7-dead-and-unused-code-report)
8. [Broken or Orphaned References](#8-broken-or-orphaned-references)
9. [Security Assessment](#9-security-assessment)
10. [Performance Assessment](#10-performance-assessment)
11. [Database Assessment](#11-database-assessment)
12. [Cross-Platform Agent Compatibility Assessment](#12-cross-platform-agent-compatibility)
13. [Architecture Review](#13-architecture-review)
14. [Technical Debt Analysis](#14-technical-debt-analysis)
15. [Prioritized Remediation Roadmap](#15-remediation-roadmap)
16. [Files Requiring Changes](#16-files-requiring-changes)

---

## 1. Executive Summary

SentinelGo is a well-structured, production-grade cross-platform Go agent that reports device inventory, audit logs, software, OS services, and EPM (Endpoint Privilege Management) telemetry to a Supabase backend. The overall engineering quality is **above average** for its domain. The codebase demonstrates mature patterns: a circuit-breaker–gated auth service, single-flight token refresh, panic recovery in task goroutines, atomic config writes, ed25519 binary signature verification, and a proper WAL-mode SQLite store for offline-first durability.

**Overall Health: GOOD — with targeted remediation required in 4 areas.**

| Category | Rating | Summary |
|---|---|---|
| Code Quality | Good | Clean structure; a few smells isolated to specific files |
| Security | Moderate | Two real vulnerabilities; remainder are hardening gaps |
| Performance | Good | One unbounded retry loop; all other patterns are correct |
| Database (local SQLite) | Good | Migrations, WAL, transactions all correct |
| Cross-Platform Compatibility | Good | Minor gaps on macOS (launchd) and Linux (systemd unit) |
| Architecture | Good | Clean separation; one structural inconsistency |
| Technical Debt | Low–Moderate | Dead code, committed binary, one duplicated builtin |
| CI/CD | Excellent | Multi-platform test matrix, govulncheck, Trivy, SonarQube |

**Scope clarification:** The original audit request referenced a "frontend" (React, Supabase RLS policies, RPCs, migrations). This repository contains **only the Go agent**. There is no frontend, no Supabase Edge Functions source, no SQL migration files, and no RLS policy definitions in this codebase. Those components must reside in a separate repository. Sections of this report that reference frontend/database architecture describe the agent's interaction surface with those external systems, not the systems themselves.

---

## 2. Critical Issues

### CRIT-01 — Compiled Binary (`sentinelgo.exe`) Committed to Repository Root

**File:** `sentinelgo.exe` (repository root)  
**Severity:** Critical  
**Category:** Security / Repository Hygiene

A Windows x64 compiled binary is committed directly to the repository root. This is dangerous for three reasons:

1. **Supply-chain attack surface.** Any contributor with push access can silently replace the binary. Users who clone the repo and run `./sentinelgo.exe` directly execute an unverified binary that bypasses the build system, signing pipeline, and all CI checks.
2. **The binary is stale and unauthenticated.** It does not carry a `.sig` signature file. The updater (`internal/updater/downloader.go`) enforces ed25519 signature verification for every update — this binary has no equivalent protection.
3. **`.gitignore` does not exclude it.** The `.gitignore` contains `*.exe` patterns for build output directories but the root-level binary is not excluded.

**Remediation:**
1. Remove `sentinelgo.exe` from the repository immediately: `git rm sentinelgo.exe`.
2. Add `/*.exe` to `.gitignore` to prevent re-introduction.
3. Audit git history to confirm no other binaries were committed (`git log --all --full-history -- "*.exe"`).

---

### CRIT-02 — `WithEnqueueRetry` Contains an Infinite Retry Loop on 5xx/Network Errors

**File:** `internal/service/rpcutil/enqueue_retry.go`  
**Severity:** Critical  
**Category:** Stability / Performance

```go
for attempt := 0; ; attempt++ {   // no termination condition
    ...
    // 5xx or network error: backoff and retry FOREVER
}
```

The retry loop for `agent_enqueue_inventory` has no maximum attempt count. On a persistent 5xx (e.g., Supabase maintenance window, misconfigured backend, network partition) the loop retries forever, blocked in `WithEnqueueRetry`, holding the scheduler task goroutine open indefinitely. Because `task.Running` stays `true`, every subsequent periodic tick for that task is skipped (the `CompareAndSwap(false, true)` guard fails), and inventory reporting silently stops — without any error surfaced to the emergency log.

The backoff caps at 5 minutes, so after the cap is reached the loop fires every 5 minutes forever, which is at least not hammering, but the goroutine never returns.

**Remediation:**
```go
const maxEnqueueAttempts = 10

for attempt := 0; attempt < maxEnqueueAttempts; attempt++ {
    ...
}
return fmt.Errorf("enqueue failed after %d attempts: %w", maxEnqueueAttempts, lastErr)
```
Alternatively, honour context cancellation as the sole termination condition but then ensure the scheduler properly cancels long-running task contexts when the agent shuts down.

---

## 3. High Priority Findings

### HIGH-01 — Process-Lock Naming Inconsistency Between Service Mode and Foreground Mode

**Files:** `cmd/sentinelgo/service/program.go`, `cmd/sentinelgo/service/lifecycle.go`  
**Severity:** High  
**Category:** Stability / Correctness

The service mode (`program.go → Start`) creates a lock named `"sentinelgo"` (version-independent, by design per the comment). The foreground mode (`lifecycle.go → RunForeground`) creates a lock named `"sentinelgo-<version>"` (version-scoped).

```go
// program.go — service mode
lf := lockfile.NewLockFile("sentinelgo")

// lifecycle.go — foreground mode
lf := lockfile.NewLockFile(fmt.Sprintf("sentinelgo-%s", version))
```

The consequence: **a service-mode instance and a foreground-mode instance can run simultaneously**, because they hold different lock files. This produces double heartbeats, double audit log uploads, and races on config writes (both goroutines calling `cfg.SaveAtomic()` from separate processes). The inline comment in `program.go` explicitly warns against version-suffixed locks — but the fix was only applied to `program.go`, not to `lifecycle.go`.

**Remediation:** Change `RunForeground` in `lifecycle.go` to use the same version-independent lock name:
```go
lf := lockfile.NewLockFile("sentinelgo")
```

---

### HIGH-02 — `AgentService.GetAgentInfo` Issues Unconstrained `SELECT *`

**File:** `internal/service/agent/agent.go`  
**Severity:** High  
**Category:** Security / Performance

```go
_, err := client.From("agents").
    Select("*", "", false).
    ExecuteToWithContext(ctx, &agents)
```

This query selects all columns from the `agents` table without a `WHERE` clause. It relies entirely on Supabase Row Level Security (RLS) to constrain the result set to the calling agent's own row. Two risks:

1. **RLS misconfiguration.** If the `agents` table RLS policy is incorrectly configured (e.g., during a migration or policy update), this query returns all agents' data instead of just the caller's.
2. **Sensitive data over-fetch.** Selecting `*` pulls columns that may be sensitive (access tokens, secrets) even when only a subset is needed.

The function is not currently called from any production path (see Section 7), which reduces immediate risk, but the pattern should be corrected before it is activated.

**Remediation:**
```go
client.From("agents").
    Select("id, hostname, status, agent_version", "", false).
    Eq("id", cfg.DeviceID).
    ExecuteToWithContext(ctx, &agents)
```

---

### HIGH-03 — `IsUnauthorized` Uses Fragile String-Matching Heuristic

**File:** `internal/service/auth/httperr.go`  
**Severity:** High  
**Category:** Security / Correctness

The `IsUnauthorized` function classifies errors as 401s by scanning the lowercased error string for substrings like `"unauthorized"`, `"jwt expired"`, `"invalid_grant"`. This pattern is fragile:

1. **False positives.** An error message containing "unauthorized" from a non-auth context (e.g., a firewall rejection message, a custom application error) will trigger session recovery unnecessarily.
2. **False negatives.** A new Supabase SDK version that changes error phrasing (e.g., from `"status 401"` to `"http 401"`) will silently break recovery, causing tasks to fail without retrying.
3. **`"forbidden"` overlap.** The check `isForbidden` also looks for `"permission denied"` and `"row-level security"` — these are application-layer terms that may appear in non-403 errors.

**Remediation:** Where possible, use structured error types or HTTP status codes rather than string scanning. For the Supabase SDK paths that return opaque strings, document the exact error format each SDK version produces and add regression tests for each substring.

---

### HIGH-04 — EPM IPC Is Windows-Only; No Unix Equivalent Exists

**Files:** `internal/epm/service_windows.go`, `internal/epm/service_other.go`, `internal/epm/socket_linux.go`, `internal/epm/socket_darwin.go`  
**Severity:** High  
**Category:** Architecture / Feature Completeness

The EPM enforcement transport is a Windows Named Pipe (`internal/epm/pipe_windows.go`). The `service_other.go` stub (`//go:build !windows`) has `Start()` and `Stop()` that are no-ops — EPM is silently disabled on Linux and macOS even when `cfg.EPMEnabled = true`.

`socket_linux.go` and `socket_darwin.go` exist, suggesting Unix domain socket transports were planned, but no `service_linux.go` or `service_darwin.go` exists to wire them in. The corresponding `socket_client_linux.go` and `socket_client_darwin.go` in `cmd/sentinelgo-epm/` are similarly orphaned.

**Remediation:** Either:
- Implement Unix domain socket enforcement transport for Linux/macOS (completing the existing skeleton), or
- Explicitly document and enforce that EPM requires Windows (`cfg.EPMEnabled` check at startup with a warning on non-Windows), so operators don't unknowingly enable EPM on Linux/macOS and believe it is active.

---

### HIGH-05 — Linux Systemd Unit Uses `Restart=on-failure` Without `RestartSec` Tuning

**File:** `cmd/sentinelgo/service/svc_linux.go`  
**Severity:** High  
**Category:** Stability / Cross-Platform

```go
const linuxUnitFmt = `...
[Service]
Type=simple
ExecStart=%s
Restart=on-failure
RestartSec=5s
...`
```

`RestartSec=5s` means after a crash the service is restarted after only 5 seconds. Without `StartLimitIntervalSec` and `StartLimitBurst`, systemd will restart indefinitely on a permanent failure (e.g., config corruption), potentially filling journals with restart noise. Additionally, `Type=simple` with a long-lived process that acquires a lock means systemd considers the service "started" as soon as `ExecStart` is invoked, not after the lock is acquired and the agent is ready. A fast restart after a crash can race against lock-file cleanup.

**Remediation:**
```ini
[Service]
Type=simple
ExecStart=%s
Restart=on-failure
RestartSec=10s
StartLimitIntervalSec=120
StartLimitBurst=5
```

---

### HIGH-06 — `osinfo.Collect()` Loads Config on Every Invocation

**File:** `internal/osinfo/collect.go`  
**Severity:** High  
**Category:** Performance / Design

```go
func Collect() *shared.SystemInfo {
    cfg, err := config.Load("")  // reads disk every single call
    if err != nil {
        cfg = &config.Config{}
    }
    ...
    AgentVersion: cfg.CurrentVersion,
```

`config.Load("")` reads the config file from disk (and calls `os.MkdirAll`, `secureDir`, and `json.Unmarshal`) every time `Collect()` is called. `Collect()` is invoked on every `agent-info-update` scheduler tick (default 5 minutes), and also from the `debug-dump`, `osinfo-json`, and `agent-info-update` CLI commands. The only reason config is loaded here is to read `cfg.CurrentVersion` for the `AgentVersion` field — config is already available at every call site.

**Remediation:** Remove the config load from `Collect()`. Instead, pass `agentVersion string` as a parameter, or inject it at construction time. All call sites already have access to the running config.

---

### HIGH-07 — `rpcutil.CallWithTimeout` Leaks a Goroutine on Timeout

**File:** `internal/service/rpcutil/rpcutil.go`  
**Severity:** High  
**Category:** Performance / Memory

```go
go func() {
    s, err := fn()
    ch <- result{s: s, err: err}  // buffered(1) — goroutine always completes
}()
select {
case r := <-ch:
    return r.s, r.err
case <-ctx.Done():
    return "", fmt.Errorf("rpc timed out ...")
}
```

The comment claims the buffer of 1 prevents a goroutine leak. This is **partially correct**: the goroutine will eventually unblock (it can always write to the channel). However, since `postgrest-go` does not honour context cancellation (acknowledged in the comment), the goroutine continues running the blocking RPC call for the full TCP timeout duration (potentially minutes) after the caller has returned. During this window, the goroutine holds an HTTP connection from the pool. Under high failure rates or repeated timeouts, connection pool exhaustion is possible.

**Remediation:** This is a known limitation of the `postgrest-go` client. The correct long-term fix is to either use the PostgREST HTTP API directly (with `http.NewRequestWithContext`) or switch to the maintained `supabase-community/postgrest-go` fork that supports context. Short-term, document the goroutine lifetime explicitly and add a connection pool cap to the client.

---

## 4. Medium Priority Findings

### MED-01 — `internal/auth/auth_logger.go` Is Completely Unused

**File:** `internal/auth/auth_logger.go`  
**Severity:** Medium  
**Category:** Dead Code

The `AuthLogger` type and all its methods (`LogAuthEvent`, `LogTokenRefresh`, `LogCircuitBreakerStateChange`, `LogAuthFailure`, `LogAuthSuccess`, `LogTokenExpiry`) exist in `internal/auth/` (distinct from `internal/service/auth/`). A grep across the entire codebase finds **zero imports or usages** of `sentinelgo/internal/auth`. This is an entire package that is compiled but never executed.

**Remediation:** Remove `internal/auth/` entirely, or integrate it into `internal/service/auth/` if structured auth event logging is desired.

---

### MED-02 — `AutoUpdateChecker` Function Is Dead Code

**File:** `internal/updater/checker.go`  
**Severity:** Medium  
**Category:** Dead Code

```go
func AutoUpdateChecker(ctx context.Context, cfg *config.Config) {
    ticker := time.NewTicker(1 * time.Hour)
    ...
}
```

`AutoUpdateChecker` is a standalone loop function that was the original auto-update mechanism. It is never called anywhere in the codebase — the scheduler's `"auto-update"` task (`handleAutoUpdate`) fully replaces it. This function creates confusion about which update path is active.

**Remediation:** Delete `AutoUpdateChecker`. The scheduler-based path is the canonical one.

---

### MED-03 — `SessionManager` in `internal/service/auth/session.go` Is Minimally Used

**File:** `internal/service/auth/session.go`  
**Severity:** Medium  
**Category:** Dead Code / Architecture

`SessionManager` wraps `Service` with an additional mutex and higher-level methods (`InitializeSession`, `RefreshTokens`, `IsAuthenticated`, `GetAccessToken`). However:
- `NewSessionManager` is never called from any production path.
- `Service` itself already implements session management, token refresh, and concurrency safety.
- `SessionManager.GetAccessToken()` and `IsAuthenticated()` duplicate functionality already on `*config.Config` (which is thread-safe via `tokenMu`).

This appears to be a partial refactor left in place. The test `recovery_test.go` appears to be the only consumer.

**Remediation:** Either remove `SessionManager` if it provides no additional value, or make it the canonical session interface and migrate all usages to it.

---

### MED-04 — `Config.SecureConfigFile()` Is an Unreachable Public Method

**File:** `internal/config/config.go`  
**Severity:** Medium  
**Category:** Dead Code

```go
func (c *Config) SecureConfigFile() error {
    return os.Chmod(c.Path, 0600)
}
```

This method is exported but never called. The actual security hardening (`winsec.SecurePath`, `secureConfigFile`) is applied inside `SaveAtomic`. `SecureConfigFile` is also incorrect on Windows — it calls `os.Chmod` which has no effect on Windows NTFS ACLs.

**Remediation:** Remove the method. The internal `secureConfigFile` call inside `SaveAtomic` is the correct implementation.

---

### MED-05 — `LoggingIntegration.CheckAgentTaskPolling` Is a No-op Placeholder

**File:** `internal/logging/logging.go`  
**Severity:** Medium  
**Category:** Dead Code

```go
func (li *LoggingIntegration) CheckAgentTaskPolling(_ context.Context) error {
    return nil
}
```

This method is exported, always returns nil, and takes no action. Its name implies it should check task polling health (for the logging service status endpoint), but it is a stub. No caller exists.

**Remediation:** Remove this method, or implement meaningful health-check logic if the intent is to expose logging service health.

---

### MED-06 — `min()` Function Redefines a Go 1.21 Built-in

**File:** `internal/store/tasks.go`  
**Severity:** Medium  
**Category:** Code Quality

```go
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}
```

Go 1.21 introduced `min` and `max` as built-in functions. This project requires Go 1.25.11. The local `min` definition shadows the built-in, which is not an error but will produce a `shadow` lint warning and creates confusion for contributors.

**Remediation:** Delete the local `min` function and use the built-in directly.

---

### MED-07 — Duplicate SQLite Database Files Committed to Repository

**Files:** `internal/sentinelgo_services.db`, `internal/scheduler/sentinelgo_services.db`, `internal/taskstore/tasks.sqlite`  
**Severity:** Medium  
**Category:** Repository Hygiene

Three SQLite database files are committed to the repository. These are runtime artifacts generated by the agent. Their presence in the repo is incorrect for two reasons:
1. They may contain locally-collected data from a developer's machine (services list, task history) that should not be in source control.
2. They can cause test failures on other machines if tests open these files and find unexpected schema or data.

**Remediation:**
- Add `*.db`, `*.sqlite` to `.gitignore`.
- Remove the committed files: `git rm --cached internal/sentinelgo_services.db internal/scheduler/sentinelgo_services.db internal/taskstore/tasks.sqlite`.

---

### MED-08 — macOS Gatekeeper Re-signing on Install Uses Hardcoded Binary Path

**File:** `cmd/sentinelgo/service/lifecycle.go`  
**Severity:** Medium  
**Category:** Cross-Platform / Hardcoding

```go
const binaryPath = "/opt/sentinelgo/sentinelgo"
_ = exec.Command("xattr", "-d", "com.apple.quarantine", binaryPath).Run()
_ = exec.Command("codesign", "--force", "--sign", "-", binaryPath).Run()
_ = exec.Command("spctl", "--add", binaryPath).Run()
```

The binary path is hardcoded. If the installation directory changes (a legitimate customization), codesigning silently fails (errors are discarded). The `os.Executable()` call used elsewhere in the updater is the correct approach.

**Remediation:**
```go
binaryPath, _ := os.Executable()
if binaryPath == "" {
    binaryPath = "/opt/sentinelgo/sentinelgo"
}
```

---

### MED-09 — `handleStop` on Linux/macOS Uses a Bare `kill` Command Without Privilege Check

**File:** `cmd/sentinelgo/cli/process.go`  
**Severity:** Medium  
**Category:** Cross-Platform / Robustness

The stop handler sends `SIGTERM` via `exec.Command("kill", strconv.Itoa(proc.PID))`, which requires the calling user to own the target process. When the agent runs as `root` (the normal service mode) and the CLI is invoked as a non-root user, the kill silently fails and the retry loop force-kills with SIGKILL — also failing silently. The user sees "All SentinelGo processes stopped" even though no process was stopped.

**Remediation:** Check the exit code of the kill command and surface a clear error message when the operation fails due to permissions. Recommend `sudo sentinelgo -stop` in the error output.

---

### MED-10 — `sonar-project.properties` Version Is Hardcoded as `1.0.0`

**File:** `sonar-project.properties`  
**Severity:** Medium  
**Category:** CI/CD

```
sonar.projectVersion=1.0.0
```

The SonarQube project version is hardcoded. SonarQube uses this to track quality trends across releases. With a static value, every scan is attributed to "1.0.0" regardless of the actual release version, making it impossible to correlate quality metrics with specific releases.

**Remediation:** Inject the version dynamically in CI from the git tag, the same way the binary version is injected:
```yaml
- name: SonarQube Scan
  env:
    SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
  run: |
    VERSION="${GITHUB_REF#refs/tags/}"
    sonar-scanner -Dsonar.projectVersion="$VERSION"
```

---

### MED-11 — `sentinelgo-epm` EPM Client Lacks Input Validation on `AppPath`

**File:** `internal/epm/pipe_windows.go`  
**Severity:** Medium  
**Category:** Security

The `pipeRequest.AppPath` field received from the client is used directly in `computeFileHashFn(req.AppPath)` and passed to `launchAsUserFn`. While the server resolves the user identity from the OS (not trusting the client), there is no validation that `AppPath` is an absolute path, is not a UNC path (`\\server\share\evil.exe`), or does not contain path traversal sequences.

**Remediation:**
```go
if !filepath.IsAbs(req.AppPath) || strings.Contains(req.AppPath, "..") {
    resp.Error = "invalid AppPath: must be an absolute path"
    return resp
}
```
Also consider rejecting UNC paths and paths outside approved directories.

---

## 5. Low Priority Findings

### LOW-01 — Windows Update Script Uses `%s` String Formatting Without Quoting Arguments

**File:** `internal/updater/installer.go`  
**Severity:** Low  
**Category:** Security / Robustness

```go
script := fmt.Sprintf(`...
move /Y "%s" "%s" >nul 2>&1
...
sc start "%s" >nul 2>&1
`, newPath, selfPath, windowsServiceName, bat)
```

`newPath` and `selfPath` are double-quoted in the batch script, which is correct for paths with spaces. However, `windowsServiceName` is inserted unquoted into `sc start`. If the service name ever contains spaces or special characters, the command would break. Currently `windowsServiceName = "SentinelGo"` which is safe, but this is fragile.

**Remediation:** Quote all interpolated values in batch scripts or use `exec.Command` with individual arguments instead of a generated script.

---

### LOW-02 — `cmd/sentinelgo/service/program.go` Logs Conflicting Startup Message

**File:** `cmd/sentinelgo/service/program.go`  
**Severity:** Low  
**Category:** Code Quality

```go
fmt.Println("Consider running './sentinelgo -stop' to stop old versions first")
```

This message appears in `main.go` every time the binary is launched without a service-mode flag, even during normal `./sentinelgo -install`. The message is misleading — it implies the user needs to stop something, which is not always true. It also prints to `stdout` in a process that may be running as a system service (where stdout is discarded).

**Remediation:** Remove the unconditional print, or gate it on a specific condition (e.g., only when another running instance is detected).

---

### LOW-03 — `dev/null` Artifact in Repository

**File:** `dev/null`  
**Severity:** Low  
**Category:** Repository Hygiene

A file named `null` exists in the `dev/` directory. This appears to be an accidental commit of a Unix `/dev/null` redirect artifact. It has no relevance to the project.

**Remediation:** `git rm dev/null` and add `dev/` to `.gitignore` if it is not needed.

---

### LOW-04 — `internal-only` File Without Extension in Repository Root

**File:** `internal-only`  
**Severity:** Low  
**Category:** Repository Hygiene

A file named `internal-only` (no extension) exists at the root. Its purpose is unclear from the filename. It is not referenced by any build file, README, or CI script.

**Remediation:** Review its contents, document it if intentional (rename with a clear extension), or remove it if it is a stale artifact.

---

### LOW-05 — `coverage` File Without Extension in Repository Root

**File:** `coverage`  
**Severity:** Low  
**Category:** Repository Hygiene

A file named `coverage` (no extension) exists at the root. Coverage output is normally named `coverage.out` (generated by `make coverage`). This may be a stale artifact from a manual run.

**Remediation:** Add `coverage` to `.gitignore` and `git rm --cached coverage`.

---

### LOW-06 — `cmd/sentinelgo/service/services.go` Missing Explicit Check

**File:** `cmd/sentinelgo/cli/services.go`  
**Severity:** Low  
**Category:** Code Quality

`HandleServicesListCommand` loads the config but ignores the loaded config for all subsequent operations:
```go
_, err := config.Load(cfgPath)
if err != nil {
    log.Printf("Warning: Could not load config: %v", err)
}
// cfg is never used after this point
```
The loaded config is discarded. The function is functional (the services service needs no config to collect), but the config load is wasted work.

**Remediation:** Remove the config load from this function since it serves no purpose.

---

### LOW-07 — `test-run/` Directory Should Be in `.gitignore`

**File:** `test-run/` (directory)  
**Severity:** Low  
**Category:** Repository Hygiene

A `test-run/` directory exists at the project root. If this is used for local test execution artifacts it should be gitignored. If it contains test fixtures it should be documented.

**Remediation:** Add `test-run/` to `.gitignore` if it is a runtime artifact directory.

---

### LOW-08 — Release Workflow's AI Notes Step Silently Degrades

**File:** `.github/workflows/release.yml`  
**Severity:** Low  
**Category:** CI/CD

The AI-generated release notes step uses `curl -sf` but falls back silently to GitHub's auto-generated notes when the AI call fails (`success=false`). This is acceptable resilience, but there is no notification when the AI step fails, so a broken GitHub token or model endpoint change goes unnoticed for potentially many releases.

**Remediation:** Add a `::warning::` annotation when AI note generation fails so it is visible in the Actions run summary without blocking the release.

---

## 6. Code Quality Assessment

### 6.1 Overall Quality

The codebase is well-written Go. It follows standard Go layout conventions, uses `internal/` correctly for private packages, separates platform-specific code via build tags and filename suffixes, and maintains a clean dependency graph. Test coverage is comprehensive for core packages (auth, config, scheduler, updater, store, epm).

### 6.2 Positive Patterns Observed

| Pattern | Location | Notes |
|---|---|---|
| Single-flight token refresh | `internal/service/auth/auth.go` | Prevents parallel refresh storms correctly |
| Panic recovery in task goroutines | `internal/scheduler/scheduler.go:runTaskHandler` | Isolates failures to individual tasks |
| Atomic config writes with temp-file rename | `internal/config/config.go:SaveAtomic` | Correct; prevents torn writes |
| ed25519 signature verification on updates | `internal/updater/downloader.go` | Fail-closed: missing .sig = abort |
| WAL-mode SQLite with single connection | `internal/store/db.go` | Correct for single-writer SQLite |
| Versioned schema migrations | `internal/store/schema.go` | Per-transaction; crash-safe |
| Circuit breaker on auth recovery | `internal/service/auth/auth.go` | Correct; backs off on persistent failures |
| Jitter on scheduler ticks | `internal/scheduler/scheduler.go` | Prevents thundering herd on fleet restart |
| Panic-safe task execution | `internal/scheduler/scheduler.go` | Recovers panics in collector goroutines |
| NUL-byte stripping before Postgres upsert | `internal/sanitize/sanitize.go` | Prevents Postgres JSONB rejection |
| Emergency log with daily rotation | `internal/emergencylog/emergencylog.go` | Always echoes to stdlib log as fallback |

### 6.3 Code Smell Inventory

| # | Smell | Location | Impact |
|---|---|---|---|
| CS-1 | Unused package `internal/auth` | `internal/auth/auth_logger.go` | Compiled dead weight |
| CS-2 | `SelectAll *` without WHERE | `internal/service/agent/agent.go` | Security gap |
| CS-3 | Shadows Go builtin `min` | `internal/store/tasks.go` | Lint warning, confusion |
| CS-4 | Config loaded inside data collector | `internal/osinfo/collect.go` | Unnecessary disk I/O per cycle |
| CS-5 | Hardcoded install path on macOS | `cmd/sentinelgo/service/lifecycle.go` | Breaks on non-standard installs |
| CS-6 | Binary artifact in repo root | `sentinelgo.exe` | Security, repo hygiene |
| CS-7 | Unconditional startup message to stdout | `cmd/sentinelgo/main.go` | Noisy, misleading |
| CS-8 | Config loaded but discarded | `cmd/sentinelgo/cli/services.go` | Wasted I/O |
| CS-9 | Placeholder no-op exported method | `internal/logging/logging.go` | Dead API surface |
| CS-10 | Stale function never called | `internal/updater/checker.go:AutoUpdateChecker` | Dead code |
| CS-11 | Infinite retry loop | `internal/service/rpcutil/enqueue_retry.go` | Goroutine starvation |
| CS-12 | Versioned vs unversioned lock inconsistency | `lifecycle.go` vs `program.go` | Double-instance risk |

### 6.4 Naming and Structure

The naming conventions are idiomatic Go throughout. Package names are lowercase single-word. Interfaces are named for behavior (`TaskHandler`, `RuleProvider`, `AuditSink`, `TokenRefresher`). Exported types and functions have appropriate GoDoc comments on the most important symbols.

One minor inconsistency: `internal/service/auth/` and `internal/auth/` both exist and both contain auth-related code. The `internal/auth/` package is unused, causing confusion about which is the canonical auth package.

---

## 7. Dead and Unused Code Report

### 7.1 Unused Packages

| Package | Path | Evidence of Non-Use |
|---|---|---|
| `auth` (logger) | `internal/auth/` | Zero imports of `sentinelgo/internal/auth` in any `.go` file |

### 7.2 Unused Functions

| Function | File | Notes |
|---|---|---|
| `AutoUpdateChecker` | `internal/updater/checker.go` | Replaced by scheduler task; no callers |
| `Config.SecureConfigFile()` | `internal/config/config.go` | Internal `secureConfigFile` is used instead; this public wrapper has no callers |
| `LoggingIntegration.CheckAgentTaskPolling` | `internal/logging/logging.go` | No-op; no callers |
| `AgentService.GetAgentInfo` | `internal/service/agent/agent.go` | No production callers found |
| `AgentService.SetAgentStatus` | `internal/service/agent/agent.go` | No production callers found |
| `LockFile.AcquireWithTimeout` | `internal/lockfile/lockfile.go` | No callers; `TryAcquire` is used everywhere |

### 7.3 Unused Types / Structs

| Type | File | Notes |
|---|---|---|
| `AuthLogger` (entire type) | `internal/auth/auth_logger.go` | Part of unused package |
| `SessionManager` | `internal/service/auth/session.go` | Only used in tests; no production wiring |

### 7.4 Unused Constants / Variables

| Symbol | File | Notes |
|---|---|---|
| `windowsServiceName` | `internal/updater/checker.go` | Used only in `installer.go`; acceptable cross-file use but worth noting |
| `taskFailureThreshold` const | `internal/scheduler/scheduler.go` | Used — not dead, listed for completeness as a tunable |

### 7.5 Orphaned / Partially Implemented Files

| File | Status | Notes |
|---|---|---|
| `internal/epm/socket_linux.go` | Partially implemented | Unix socket server scaffolding; not wired into `service_linux.go` |
| `internal/epm/socket_darwin.go` | Partially implemented | Unix socket server scaffolding; not wired into `service_darwin.go` |
| `internal/epm/socket_client_linux.go` | Partially implemented | Client side for EPM on Linux; `cmd/sentinelgo-epm/main_linux.go` not fully wired |
| `internal/epm/socket_client_darwin.go` | Partially implemented | Client side for EPM on macOS; `cmd/sentinelgo-epm/main_darwin.go` not fully wired |
| `internal/auth/auth_logger.go` | Unused | Entire package dead |

### 7.6 Committed Runtime Artifacts (Should Be in .gitignore)

| File | Type | Notes |
|---|---|---|
| `sentinelgo.exe` | Compiled binary | Should never be in repo |
| `internal/sentinelgo_services.db` | SQLite DB | Runtime artifact |
| `internal/scheduler/sentinelgo_services.db` | SQLite DB | Runtime artifact |
| `internal/taskstore/tasks.sqlite` | SQLite DB | Runtime artifact |
| `coverage` | Coverage output | Runtime artifact |
| `dev/null` | Redirect artifact | Accidental commit |

---

## 8. Broken or Orphaned References

### 8.1 Incomplete / Orphaned EPM Transport for Linux and macOS

**Cross-references:** `internal/epm/socket_linux.go` ↔ `internal/epm/service_other.go`  

`socket_linux.go` implements a Unix domain socket server. `service_other.go` (the non-Windows stub for `epm.Service`) ignores it entirely — `Start()` is a no-op. The `socket_client_linux.go` and `cmd/sentinelgo-epm/main_linux.go` exist but connect to a socket that is never served. This means EPM requests on Linux/macOS connect to a non-listening socket and fail silently.

### 8.2 `cmd/sentinelgo/cli/software.go` References `swsvc.SendByRPC` Which May Not Exist on All Platforms

The `HandleSoftwareSync` CLI function calls `svc.SendByRPC(...)`, but the main scheduler path calls `svc.SendByRPCIfChanged(...)`. These are distinct methods. The CLI sync path bypasses the change-detection logic, meaning it always sends even when the software list is unchanged. This is acceptable for a forced sync but should be documented. More importantly, if `SendByRPC` is removed or renamed in a refactor, this CLI function would silently stop working.

### 8.3 `sonar-project.properties` References `scripts/` but Scripts Directory Is Excluded

```
sonar.exclusions=...scripts/**...
```

The `scripts/` directory contains production Go code (`scripts/sign`, `scripts/keygen`, `scripts/filtercoverage`). Excluding it from SonarQube analysis means the signing script, keygen, and coverage filter are never statically analyzed for quality or security issues. This is an oversight in the exclusions list.

### 8.4 `CLAUDE.md` Architecture Section Is Partially Stale

**File:** `CLAUDE.md`

The architecture description in `CLAUDE.md` lists:
```
internal/
  heartbeat/   # payload generation and Supabase API calls
  constants/   # shared constants
```

Neither `internal/heartbeat/` nor `internal/constants/` exists in the current codebase. The heartbeat functionality lives in `internal/service/agent/agent.go` (via `UpdateAgentInfo`), and constants are distributed across `internal/models/` and package-local constants. The documentation is describing an older codebase structure.

**Remediation:** Update `CLAUDE.md` to reflect the actual directory layout.

### 8.5 `settings.json` at Repository Root

**File:** `settings.json`

A `settings.json` file exists at the repository root. Its purpose is unclear — it is not referenced by any build file, test, or documentation. If it is an editor settings file (VS Code), it should be in `.vscode/settings.json`. If it is an agent configuration sample, it should be documented.

---

## 9. Security Assessment

### 9.1 Authentication and Token Handling

| Aspect | Status | Notes |
|---|---|---|
| Credential storage | ✅ Good | Config stored at 0600; SYSTEM/Admins-only DACL on Windows via `winsec.SecurePath` |
| Token refresh | ✅ Good | Proactive refresh 5 min before expiry; single-flight; retry with backoff |
| Token persistence | ✅ Good | Atomic rename; SaveAtomic serialises concurrent writes |
| Bootstrap login | ✅ Good | `agent-login` edge function exchanges agent_id + agent_secret for JWT |
| Token rotation | ✅ Good | Refresh token rotated on every use; old token persisted until new one saved |
| ErrLoginRejected distinction | ✅ Good | Credentials rejection distinguished from transient failure; reprovision state |
| `IsUnauthorized` heuristic | ⚠️ Fragile | String-matching; see HIGH-03 |
| AgentSecret in config file | ⚠️ Noted | `agent_secret` persists in plaintext config.json; protected by OS permissions |

### 9.2 Update Security

| Aspect | Status | Notes |
|---|---|---|
| ed25519 signature verification | ✅ Good | `verifySignature` / `verifySignatureBytes`; fail-closed on missing .sig |
| SHA256 checksum verification | ✅ Good | Computed during download; compared against RPC manifest |
| Downgrade prevention | ✅ Good | `isNewerVersion` enforces strictly-newer semantic version |
| Update script ACL (Windows) | ✅ Good | `winsec.SecurePath(bat)` — SYSTEM/Admins only |
| Staged binary ACL (Windows) | ✅ Good | `winsec.SecurePath(newPath)` — prevents swap between download and install |
| macOS Gatekeeper re-sign | ✅ Good | `recodesignForGatekeeper` after `atomicReplace` |
| Backup before update | ✅ Good | `createBackup()` before any replace; rollback on failure |
| Hardcoded binary path on macOS install | ⚠️ Fragile | See MED-08 |

### 9.3 EPM Security

| Aspect | Status | Notes |
|---|---|---|
| Server-side identity resolution | ✅ Excellent | `GetNamedPipeClientProcessId` → WTS session → token; client cannot claim false identity |
| Server-side hash computation | ✅ Excellent | `computeFileHashFn(req.AppPath)` on server; client-supplied hash ignored |
| Default-deny policy | ✅ Good | `Engine.Evaluate` returns `Allowed=false` when no rule matches |
| Policy expiry enforcement | ✅ Good | Expired rules skipped in `Evaluate` |
| Pipe DACL | ✅ Good | `D:(A;;GA;;;AU)` — allows authenticated users to connect |
| AppPath input validation | ⚠️ Gap | No absolute-path or UNC-path check; see MED-11 |
| EPM on Linux/macOS | ❌ Non-functional | `service_other.go` is a stub; see HIGH-04 |

### 9.4 Task Execution Security

| Aspect | Status | Notes |
|---|---|---|
| Script download over authenticated HTTPS | ✅ Good | Bearer token + apikey on storage download |
| Script size cap | ✅ Good | `io.LimitReader(resp.Body, 10*1024*1024)` |
| Script stored in temp dir | ✅ Good | `os.MkdirTemp("", "sentinel-task-"+task.ID)` |
| Temp dir cleaned on completion | ✅ Good | `defer os.RemoveAll(tempDir)` |
| Task timeout | ✅ Good | 30-minute default; watchdog enforces hard deadline |
| Script authentication on macOS/Linux | ⚠️ Noted | Scripts execute with agent's privileges (root); no content hash verification before execution |
| PowerShell -ExecutionPolicy Bypass | ⚠️ Noted | `executor_windows.go` uses `-ExecutionPolicy Bypass`; acceptable since script is from authenticated storage, but worth documenting |
| No signature verification on scripts | ⚠️ Gap | Unlike binaries (ed25519 verified), scripts are not signed; authentication relies solely on Supabase storage auth |

### 9.5 Configuration Security

| Aspect | Status | Notes |
|---|---|---|
| URL validation | ✅ Good | `isValidURL` checks scheme and host |
| Path traversal prevention | ✅ Good | `filepath.Clean` + `filepath.IsAbs` check on config path |
| Config directory hardening | ✅ Good | `secureDir` on config directory creation |
| Concurrent config write | ✅ Good | `tokenMu` mutex; unique temp file name per SaveAtomic call |
| Interval validation | ✅ Good | Validates intervals > 0 in `validateConfig` |
| Sensitive data in emergency log | ✅ Good | `sanitize.ForLog` strips log injection characters; no token values logged |

---

## 10. Performance Assessment

### 10.1 Scheduler Performance

The scheduler is efficient. Key design choices that prevent common performance pitfalls:

- **Jitter on first tick** prevents thundering-herd on fleet-wide restarts.
- **`Running` atomic flag** ensures no task runs concurrently with itself.
- **`taskFailureThreshold` = 3** before emergency log — avoids log spam on transient failures.
- **`agentInfoForceResend` = 1h** + SHA-256 fingerprint prevents uploading unchanged inventory every tick.
- **`collectTimeout` = 90s** on `osinfo.Collect()` prevents a hung gopsutil from holding the task goroutine forever.

### 10.2 Performance Issues Found

| # | Issue | Location | Impact |
|---|---|---|---|
| P-1 | Infinite retry loop | `rpcutil/enqueue_retry.go` | Critical — goroutine starvation (see CRIT-02) |
| P-2 | Config loaded on every osinfo.Collect() | `internal/osinfo/collect.go` | Low — 1 disk read per 5-min cycle |
| P-3 | Goroutine outlives its context after RPC timeout | `rpcutil/rpcutil.go:CallWithTimeout` | Medium — connection pool pressure under sustained failures |
| P-4 | `GetAssignedTasks()` emits 3 diagnostic queries unconditionally | `internal/store/tasks.go` | Low — SQLite; negligible unless task table grows large |
| P-5 | `DeleteNotIn` builds dynamic SQL with N placeholders | `internal/store/software.go` | Low — acceptable for typical software list sizes (<5000 rows) |

### 10.3 `GetAssignedTasks()` Diagnostic Over-logging

```go
// From store/tasks.go
var totalCount int
_ = s.db.QueryRow("SELECT COUNT(*) FROM tasks").Scan(&totalCount)
// ...
rowsStatus, err := s.db.Query("SELECT status, COUNT(*) FROM tasks GROUP BY status")
```

Three diagnostic queries run on every `GetAssignedTasks()` call, including two that scan the full table. In production these run every polling interval (default 5 minutes) and are low cost. However, as the task table grows (tasks are cleaned up after completion, so growth is bounded), they add unnecessary overhead. Consider removing these debug logs from the production path or gating them behind a verbose log level.

### 10.4 Memory Considerations

- **Audit log subscription channel** is capped at 256 (`realtimeChanSize`). If the subscription goroutine falls behind, events are dropped silently. This is intentional (real-time events supplement batch collection; batch is the at-least-once path).
- **`maxDebugAuditEntries = 500`** caps debug dump output, preventing OOM on very busy hosts.
- **Software enrichment** reads full binary files for SHA-256 hashing. On hosts with thousands of large binaries, this can spike memory during the hashing pass. The hash cache mitigates repeat hashing, but the first full scan can be expensive.

---

## 11. Database Assessment

This section covers the agent's **local SQLite stores**. The Supabase PostgreSQL backend and its schemas, migrations, RLS policies, and RPCs are not present in this repository and cannot be audited here.

### 11.1 SQLite Store Architecture

The agent maintains four independent SQLite databases, each with its own migration system:

| Database | File | Purpose |
|---|---|---|
| Software catalog | `sentinelgo_software.db` | Local cache of installed software; hash cache |
| Services store | `sentinelgo_services.db` | Local cache of OS services; dedup/prune support |
| Task queue | `tasks.sqlite` | Offline-first task queue; crash recovery |
| EPM store | `sentinelgo_epm.db` | Policy rules + elevation audit log |

### 11.2 Schema Design Quality

**Positive:**
- All tables use `CREATE TABLE IF NOT EXISTS` — idempotent.
- Unique constraints on composite keys: `UNIQUE(agent_id, name, source)` in software; `UNIQUE INDEX` on `request_id` in epm_audit_log.
- `ON CONFLICT DO UPDATE` (upsert) with field-level merge logic (SHA256 hash preserved when new value is empty).
- Versioned migrations via `schema_version` table; each migration runs in its own transaction; crash leaves version un-bumped.
- WAL mode + `busy_timeout(5000)` + `MaxOpenConns(1)`.

**Issues:**

| # | Issue | Table | Notes |
|---|---|---|---|
| DB-1 | No `VACUUM` or periodic maintenance | All stores | Long-running agents accumulate page fragmentation; no scheduled VACUUM |
| DB-2 | `tasks` table grows unbounded until `ClearCompletedTasks` is called | `tasks` | `ClearCompletedTasks` exists but is never called from a scheduled task |
| DB-3 | `epm_audit_log` grows unbounded | `epm_audit_log` | Synced rows are never deleted; only `synced` flag is set |
| DB-4 | Diagnostic `SELECT COUNT(*)` and `GROUP BY status` in hot path | `tasks` | See P-4 in Performance section |
| DB-5 | `software` `file_path` column not indexed | `software` | Hash enrichment queries by name+source (indexed), but path-based lookups are O(n) |

### 11.3 Migration Integrity

The migration system is correct. Key design decisions:
- `INSERT INTO schema_version` on v0→v1, `UPDATE` on subsequent migrations — this correctly handles fresh databases vs upgrades.
- `ALTER TABLE ADD COLUMN` for v2 upgrades (software, EPM) — backward-compatible with no data migration needed.
- Each migration in its own transaction — a crash mid-migration leaves the version un-bumped and the migration retries on next start.

**One gap:** There is no test that validates the migration path from v0 to current. The comprehensive tests (`*_comprehensive_test.go`) test the current schema but not the upgrade path from a previous schema version.

### 11.4 Task Queue Durability

The task queue implements robust crash-recovery semantics:
- `MarkTaskExecuting` transitions `assigned → executing` before script runs; prevents re-execution on restart.
- `ResetInterruptedTasks` on startup moves `executing → failed` for tasks that were mid-run at crash.
- `restartctx` (restart context file) allows the rebooted binary to retroactively mark reboot/update tasks as success.
- `MaxRetryAttempts = 3` prevents infinite retry loops.
- `GetRetryableTasks` + `ResetOldFailedTasks` implement proper cooldown-gated retries.

This is well-implemented and correct.

### 11.5 Missing: `ClearCompletedTasks` Is Never Called Automatically

`TaskStore.ClearCompletedTasks(olderThan)` exists but is never called from any scheduled task or lifecycle method. Completed tasks accumulate indefinitely in the SQLite database. On long-lived agents executing many tasks, the database will grow unboundedly.

**Remediation:** Add a scheduled cleanup task (e.g., daily) that calls `ClearCompletedTasks(time.Now().Add(-7 * 24 * time.Hour))`.

---

## 12. Cross-Platform Agent Compatibility

### 12.1 Build and Distribution

| Platform | Architecture | Build | Install Script | Notes |
|---|---|---|---|---|
| Windows | amd64 | ✅ | `install.bat` | Binary + EPM binary |
| Linux | amd64 | ✅ | `install.sh` | |
| Linux | arm64 | ✅ | `install.sh` | |
| macOS | amd64 | ✅ | `install.command` | Intel Mac |
| macOS | arm64 | ✅ | `install.command` | Apple Silicon |
| Windows | arm64 | ❌ Not built | — | Excluded from Makefile; acceptable |

`verify-cross` Makefile target type-checks all 5 release targets from a single host — good CI hygiene.

### 12.2 Service Registration

| Platform | Mechanism | Status | Notes |
|---|---|---|---|
| Windows | Windows SCM (`mgr.CreateService`) | ✅ Correct | `StartType=Automatic`; event log registration |
| Linux | systemd unit file (`/etc/systemd/system/`) | ✅ Correct | `Restart=on-failure`; needs `StartLimitBurst` (see HIGH-05) |
| macOS | launchd plist (`/Library/LaunchDaemons/`) | ✅ Correct | `KeepAlive=true`; loads via `launchctl bootstrap` |

### 12.3 Feature Matrix by Platform

| Feature | Windows | Linux | macOS | Notes |
|---|---|---|---|---|
| Service install/uninstall | ✅ | ✅ | ✅ | |
| Device registration / heartbeat | ✅ | ✅ | ✅ | |
| OS info collection | ✅ | ✅ | ✅ | Platform-specific files in `osinfo/` |
| Software inventory | ✅ | ✅ | ✅ | Registry / dpkg-apt-brew / Applications + Homebrew |
| OS services collection | ✅ | ✅ | ✅ | SCM / systemd / launchctl |
| Audit log collection | ✅ | ✅ | ✅ | Windows Event Log / journald / `log show` |
| Self-update | ✅ | ✅ | ✅ | Windows: batch script; macOS: exit+launchd; Linux: exit+systemd |
| Task execution | ✅ | ✅ | ✅ | PowerShell / bash / bash |
| EPM enforcement | ✅ | ❌ Stub | ❌ Stub | Unix sockets present but not wired |
| Firewall management | ✅ | ✅ | ✅ | `netsh` / `ufw` / `socketfilterfw` |
| Reboot | ✅ | ✅ (root req.) | ✅ | |
| Registry tasks | ✅ Windows only | N/A | N/A | `native/registry.go` |
| Process lock | ✅ | ✅ | ✅ | Platform-specific lock file implementation |
| Config file security | ✅ (DACL) | ✅ (0600) | ✅ (0600) | |

### 12.4 Platform-Specific Issues Found

**Windows:**
- Update script (`sentinelgo_update.bat`) uses `ping -n 3 127.0.0.1` as a delay mechanism — works in Session 0 but is a non-obvious hack. A comment explaining why `timeout` cannot be used is present (`CLAUDE.md`) but not in the code itself.
- `taskkill /F /PID` in the stop handler force-kills without a graceful SIGTERM equivalent.

**Linux:**
- `device-reboot` checks `os.Getuid() != 0` and fails if not root. On some distributions the agent may run as a system user (not `root`) with `CAP_SYS_BOOT` capability. A capability check would be more portable.
- The systemd unit `ExecStart` line is built by string-joining executable path + arguments. If the binary path contains spaces (uncommon but possible in non-standard installs), the unit file would be malformed.

**macOS:**
- Gatekeeper re-signing in `HandleInstall` uses a hardcoded binary path (see MED-08).
- The macOS launchd service uses `svc_darwin.go → Run()` for the lifecycle, which is correct. `Install()` and `Uninstall()` return `fmt.Errorf("unreachable")` — this is intentional but could cause confusion if the `AgentService` interface is used generically.
- `launchctl bootstrap system` vs `launchctl load` difference on macOS 10.11+ is handled correctly in `launchd.go`.

### 12.5 Audit Log Collection Platform Coverage

| Platform | Mechanism | Sources |
|---|---|---|
| Windows | Windows Event Log (wevtapi) | Security, System, Application channels |
| Linux | `journalctl -o json` subprocess | systemd journal |
| macOS | `log show --style ndjson` subprocess | Unified Log (auth, security events) |

The subprocess approach (rather than `libsystemd`/OSLog C bindings) is correct — it preserves `CGO_ENABLED=0` and cross-compilation.

---

## 13. Architecture Review

### 13.1 Overall Architecture

SentinelGo follows a clean three-layer architecture:

```
┌─────────────────────────────────────────────────────────┐
│  cmd/sentinelgo  (entry points, CLI, service lifecycle)  │
├─────────────────────────────────────────────────────────┤
│  internal/         (private packages — all business logic)│
│  ├── config/       Config loading, validation, persistence│
│  ├── scheduler/    Dependency-ordered task scheduler      │
│  ├── service/      auth, agent, software, services, task  │
│  ├── osinfo/       Cross-platform system info collection  │
│  ├── epm/          Privilege management engine + IPC      │
│  ├── store/        SQLite stores (software, tasks, EPM)   │
│  ├── logging/      Audit log pipeline                     │
│  ├── updater/      Self-update mechanism                  │
│  └── resilience/   Circuit breaker                        │
├─────────────────────────────────────────────────────────┤
│  Supabase (external)                                      │
│  ├── agent-login   Edge Function (JWT issuance)           │
│  ├── PostgREST     RPCs (enqueue_inventory, get_tasks…)   │
│  └── Storage       agent-releases bucket (binary + .sig)  │
└─────────────────────────────────────────────────────────┘
```

### 13.2 What Works Well

1. **`MainIntegration` orchestrator pattern.** Explicit startup ordering, each step in a named method. Error in any step propagates to the service manager (fails the service start, triggering restart policy) rather than silently running degraded.

2. **Offline-first task queue.** Task polling → SQLite → execution → sync is correct. Crash recovery via `executing → failed` on startup prevents re-execution of dangerous tasks (reboot, update).

3. **Auth service design.** Single-flight refresh, single-flight recovery, circuit breaker, `needsReprovision` flag — all correct patterns for a long-running service.

4. **EPM engine design.** Policy evaluation is pure Go (no I/O), making it fully testable. Server-side identity resolution and hash computation are correct security design.

5. **CI/CD pipeline.** Testing on all three OS runners, lint on all three GOOS targets, govulncheck, Trivy, SonarQube — this is a mature pipeline.

### 13.3 Structural Improvement Recommendations

**Recommendation 1: Unify the two `auth` packages**

`internal/auth/` and `internal/service/auth/` co-exist. The former is unused. Removing `internal/auth/` eliminates the confusion.

**Recommendation 2: Extract `osinfo.Collect()` version parameter**

The config load in `osinfo.Collect()` is an architectural seam issue — the OS info collector should not know about config. Passing `agentVersion string` as a parameter cleanly separates concerns and removes the disk I/O from data collection.

**Recommendation 3: Add a `TaskCleanup` scheduled task**

`ClearCompletedTasks` exists but is never scheduled. A daily cleanup task would prevent unbounded SQLite growth. This is a one-function addition to `MainIntegration.configureScheduledTasks()`.

**Recommendation 4: Complete or remove EPM Unix transport**

The partial Unix socket implementation (`socket_linux.go`, `socket_darwin.go`) is an incomplete feature. It should either be completed and wired in, or removed to reduce confusion. Leaving orphaned production code in place creates maintenance burden and misleads contributors into thinking EPM works on Linux/macOS.

**Recommendation 5: Cap `WithEnqueueRetry`**

The infinite retry loop is a structural bug. A finite retry count (10 attempts) with the existing exponential backoff provides 99.9% of the resilience benefit without the goroutine starvation risk.

**Recommendation 6: Structured Logging**

The codebase uses the standard `log` package throughout. For a production agent that runs as a system service, structured logging (e.g., `log/slog` from Go 1.21+, already available at Go 1.25.11) would significantly improve observability. Log entries are currently free-form strings, making filtering and alerting difficult in log aggregation systems (journald, Windows Event Log, CloudWatch).

The project already has Go 1.21+ as the minimum version, so `log/slog` is available without adding a dependency.

### 13.4 Dependency Architecture Assessment

| Dependency | Version | Role | Health |
|---|---|---|---|
| `github.com/shirou/gopsutil/v4` | v4.26.5 | OS metrics collection | ✅ Active; v4 is current |
| `github.com/supabase-community/supabase-go` | v0.0.4 | Supabase client | ⚠️ Pre-1.0; limited updates |
| `github.com/supabase-community/postgrest-go` | v0.0.12 | PostgREST client (ignores context) | ⚠️ Pre-1.0; context gap documented |
| `modernc.org/sqlite` | v1.52.0 | Pure-Go SQLite (CGO_ENABLED=0) | ✅ Correct choice; actively maintained |
| `github.com/google/uuid` | v1.6.0 | UUID generation | ✅ |
| `golang.org/x/sys` | v0.46.0 | Windows API, syscalls | ✅ |
| `github.com/yusufpapurcu/wmi` | v1.2.4 | Windows WMI queries | ✅ Windows-only |

**Concern:** `supabase-community/supabase-go` and `supabase-community/postgrest-go` are both pre-1.0 packages with limited maintenance activity. The context-cancellation gap in `postgrest-go` (documented and worked around via `CallWithTimeout`) is a known technical debt item. Monitoring for upstream fixes or migrating to direct HTTP calls for these RPCs is advisable.

---

## 14. Technical Debt Analysis

### 14.1 Debt Inventory

| ID | Item | Category | Estimated Effort | Risk if Unaddressed |
|---|---|---|---|---|
| TD-1 | Infinite retry loop in enqueue_retry.go | Stability | 30 min | High — goroutine starvation |
| TD-2 | `sentinelgo.exe` committed to repo | Security | 15 min | High — supply-chain |
| TD-3 | Foreground lock name inconsistency | Stability | 15 min | Medium — double-instance |
| TD-4 | `internal/auth/` entire unused package | Dead code | 5 min | Low — compile overhead |
| TD-5 | `AutoUpdateChecker` dead function | Dead code | 5 min | Low — confusion |
| TD-6 | EPM Unix transport incomplete | Feature gap | Large | Medium — misleading |
| TD-7 | `osinfo.Collect()` loads config | Design | 1 hour | Low |
| TD-8 | `min()` shadows Go 1.21 builtin | Code quality | 5 min | Low |
| TD-9 | Committed SQLite runtime artifacts | Hygiene | 10 min | Low |
| TD-10 | `postgrest-go` ignores context | Upstream | Unknown | Medium — connection leaks |
| TD-11 | No task cleanup scheduled | Stability | 30 min | Medium — unbounded DB growth |
| TD-12 | No structured logging | Observability | Large | Low — debugging difficulty |
| TD-13 | `CLAUDE.md` architecture stale | Documentation | 30 min | Low — contributor confusion |
| TD-14 | `sonar-project.properties` hardcoded version | CI | 15 min | Low — trend tracking broken |
| TD-15 | `GetAgentInfo` uses SELECT * | Security | 15 min | Medium |
| TD-16 | EPM `AppPath` not validated | Security | 30 min | Medium |
| TD-17 | `ClearCompletedTasks` never called | Stability | 30 min | Medium — DB growth |
| TD-18 | Systemd unit missing restart limits | Stability | 15 min | Medium — restart loop risk |
| TD-19 | Script execution not hash-verified | Security | Large | Medium |

### 14.2 Technical Debt Score by Category

| Category | Items | Total Effort | Priority |
|---|---|---|---|
| Critical stability | 2 | ~45 min | Immediate |
| Security hardening | 4 | ~2 hours | Sprint 1 |
| Dead code removal | 5 | ~30 min | Sprint 1 |
| Incomplete features | 1 | Large | Sprint 2 |
| Database maintenance | 2 | ~1 hour | Sprint 1 |
| Documentation/hygiene | 5 | ~1 hour | Sprint 2 |
| Structural improvements | 3 | ~4 hours | Sprint 2–3 |

**Total estimated effort for all items: ~12–16 engineer-hours** (excluding EPM Unix transport and structured logging which are large features).

---

## 15. Remediation Roadmap

### Phase 1 — Immediate (Before Next Release)

These items carry the highest risk if left unaddressed. All are small, targeted changes.

| # | Action | File(s) | Effort |
|---|---|---|---|
| R-1 | **Remove `sentinelgo.exe` from repo; add `/*.exe` to .gitignore** | `sentinelgo.exe`, `.gitignore` | 15 min |
| R-2 | **Cap `WithEnqueueRetry` at 10 attempts** | `internal/service/rpcutil/enqueue_retry.go` | 30 min |
| R-3 | **Fix foreground lock name to match service lock name** | `cmd/sentinelgo/service/lifecycle.go` | 15 min |
| R-4 | **Remove committed SQLite/DB runtime artifacts** | `internal/*.db`, `internal/scheduler/*.db`, `internal/taskstore/*.sqlite` | 10 min |
| R-5 | **Add DB artifacts to .gitignore** | `.gitignore` | 5 min |

### Phase 2 — Sprint 1 (Within 2 Weeks)

Security hardening and dead code removal. All low-risk, high-value changes.

| # | Action | File(s) | Effort |
|---|---|---|---|
| R-6 | **Remove `internal/auth/` unused package** | `internal/auth/` | 5 min |
| R-7 | **Remove `AutoUpdateChecker` dead function** | `internal/updater/checker.go` | 5 min |
| R-8 | **Remove `Config.SecureConfigFile()` public dead method** | `internal/config/config.go` | 5 min |
| R-9 | **Remove `LoggingIntegration.CheckAgentTaskPolling()` no-op** | `internal/logging/logging.go` | 5 min |
| R-10 | **Delete local `min()` function; use Go builtin** | `internal/store/tasks.go` | 5 min |
| R-11 | **Add `AppPath` absolute-path validation in EPM pipe server** | `internal/epm/pipe_windows.go` | 30 min |
| R-12 | **Fix `GetAgentInfo` to use column selection + WHERE clause** | `internal/service/agent/agent.go` | 15 min |
| R-13 | **Schedule `ClearCompletedTasks` (weekly)** | `internal/main_integration.go` | 30 min |
| R-14 | **Add `StartLimitIntervalSec`/`StartLimitBurst` to systemd unit** | `cmd/sentinelgo/service/svc_linux.go` | 15 min |
| R-15 | **Inject `agentVersion` into `osinfo.Collect()` as a parameter** | `internal/osinfo/collect.go`, all call sites | 1 hour |
| R-16 | **Remove `coverage`, `dev/null`, `internal-only` from repo** | repo root | 5 min |

### Phase 3 — Sprint 2 (Within 4 Weeks)

Structural improvements and documentation.

| # | Action | File(s) | Effort |
|---|---|---|---|
| R-17 | **Update `CLAUDE.md` architecture section to match actual layout** | `CLAUDE.md` | 30 min |
| R-18 | **Add AI release note step failure annotation to release workflow** | `.github/workflows/release.yml` | 15 min |
| R-19 | **Fix SonarQube version injection in CI** | `sonar-project.properties`, CI workflow | 15 min |
| R-20 | **Fix macOS install binary path to use `os.Executable()`** | `cmd/sentinelgo/service/lifecycle.go` | 15 min |
| R-21 | **Remove `SessionManager` or promote it to canonical session API** | `internal/service/auth/session.go` | 1–2 hours |
| R-22 | **Add migration path tests (v0 → current) for all stores** | `internal/store/*_test.go` | 2 hours |
| R-23 | **Add EPM build-time warning on non-Windows when enabled** | `internal/epm/service_other.go` | 30 min |

### Phase 4 — Backlog (Future Sprints)

Larger features and structural improvements.

| # | Action | Effort |
|---|---|---|
| R-24 | Implement EPM Unix domain socket transport for Linux/macOS | Large (1–2 weeks) |
| R-25 | Migrate `log.Printf` calls to `log/slog` for structured logging | Large (3–5 days) |
| R-26 | Replace `postgrest-go` RPC calls with direct `net/http` (context support) | Medium (2–3 days) |
| R-27 | Add script content hash/signature verification before execution | Large (1 week) |

---

## 16. Files Requiring Changes

The following files have identified issues that require code or configuration changes. Files are ordered by priority.

### Phase 1 — Immediate

| File | Change Required | Finding |
|---|---|---|
| `sentinelgo.exe` | Delete from repository | CRIT-01 |
| `.gitignore` | Add `/*.exe`, `*.db`, `*.sqlite`, `coverage`, `dev/`, `test-run/` | CRIT-01, MED-07 |
| `internal/service/rpcutil/enqueue_retry.go` | Cap retry loop at N attempts | CRIT-02 |
| `cmd/sentinelgo/service/lifecycle.go` | Fix foreground lock name; fix macOS binary path | HIGH-01, MED-08 |
| `internal/sentinelgo_services.db` | Delete (runtime artifact) | MED-07 |
| `internal/scheduler/sentinelgo_services.db` | Delete (runtime artifact) | MED-07 |
| `internal/taskstore/tasks.sqlite` | Delete (runtime artifact) | MED-07 |
| `coverage` | Delete (runtime artifact) | LOW-05 |
| `dev/null` | Delete (accidental commit) | LOW-03 |

### Phase 2 — Sprint 1

| File | Change Required | Finding |
|---|---|---|
| `internal/auth/auth_logger.go` | Delete entire file (and package) | MED-01 |
| `internal/auth/auth_logger_test.go` | Delete | MED-01 |
| `internal/updater/checker.go` | Remove `AutoUpdateChecker` function | MED-02 |
| `internal/config/config.go` | Remove `SecureConfigFile()` method | MED-04 |
| `internal/logging/logging.go` | Remove `CheckAgentTaskPolling()` method | MED-05 |
| `internal/store/tasks.go` | Remove local `min()` function | MED-06 |
| `internal/epm/pipe_windows.go` | Add `AppPath` absolute-path validation | MED-11 |
| `internal/service/agent/agent.go` | Fix `GetAgentInfo` to select specific columns with WHERE | HIGH-02 |
| `internal/main_integration.go` | Add weekly `ClearCompletedTasks` scheduled task | DB-2 |
| `cmd/sentinelgo/service/svc_linux.go` | Add `StartLimitIntervalSec`/`StartLimitBurst` to unit template | HIGH-05 |
| `internal/osinfo/collect.go` | Remove `config.Load("")` call; accept version as parameter | HIGH-06 |

### Phase 3 — Sprint 2

| File | Change Required | Finding |
|---|---|---|
| `CLAUDE.md` | Update architecture section to match actual directory structure | SEC-8.4 |
| `.github/workflows/release.yml` | Add `::warning::` annotation on AI note failure | LOW-08 |
| `sonar-project.properties` | Inject version dynamically from CI | MED-10 |
| `cmd/sentinelgo/main.go` | Remove unconditional startup message to stdout | LOW-02 |
| `cmd/sentinelgo/cli/services.go` | Remove unused config load | LOW-06 |
| `internal/service/auth/session.go` | Remove `SessionManager` or wire into production code | MED-03 |
| `internal/epm/service_other.go` | Add startup warning when EPM enabled on non-Windows | HIGH-04 |
| `settings.json` | Clarify purpose, move to `.vscode/`, or delete | SEC-8.5 |
| `internal-only` | Review and rename/delete | LOW-04 |

### Phase 4 — Backlog

| File | Change Required | Finding |
|---|---|---|
| `internal/epm/service_linux.go` (new) | Implement Unix socket EPM service | HIGH-04 |
| `internal/epm/service_darwin.go` (new) | Implement Unix socket EPM service | HIGH-04 |
| `internal/service/auth/httperr.go` | Replace string matching with structured error types | HIGH-03 |
| `internal/service/rpcutil/rpcutil.go` | Document goroutine lifetime; add connection pool limit | HIGH-07 |
| All `log.Printf` call sites | Migrate to `log/slog` for structured logging | Architecture |

---

---

## Appendix A — Finding Reference Index

| ID | Title | Severity | Phase |
|---|---|---|---|
| CRIT-01 | `sentinelgo.exe` committed to repository | Critical | 1 |
| CRIT-02 | Infinite retry loop in `enqueue_retry.go` | Critical | 1 |
| HIGH-01 | Foreground/service lock name inconsistency | High | 1 |
| HIGH-02 | `GetAgentInfo` uses unconstrained `SELECT *` | High | 2 |
| HIGH-03 | `IsUnauthorized` fragile string-matching | High | 4 |
| HIGH-04 | EPM IPC Windows-only; Unix transports orphaned | High | 4 |
| HIGH-05 | Systemd unit missing restart limits | High | 2 |
| HIGH-06 | `osinfo.Collect()` loads config on every call | High | 2 |
| HIGH-07 | `CallWithTimeout` goroutine outlives context | High | 4 |
| MED-01 | `internal/auth/` entirely unused package | Medium | 2 |
| MED-02 | `AutoUpdateChecker` dead function | Medium | 2 |
| MED-03 | `SessionManager` minimally used | Medium | 3 |
| MED-04 | `Config.SecureConfigFile()` dead public method | Medium | 2 |
| MED-05 | `CheckAgentTaskPolling` no-op placeholder | Medium | 2 |
| MED-06 | `min()` shadows Go 1.21 builtin | Medium | 2 |
| MED-07 | SQLite runtime artifacts committed to repo | Medium | 1 |
| MED-08 | macOS install uses hardcoded binary path | Medium | 3 |
| MED-09 | `kill` command lacks privilege check in stop handler | Medium | 3 |
| MED-10 | SonarQube version hardcoded | Medium | 3 |
| MED-11 | EPM `AppPath` lacks input validation | Medium | 2 |
| LOW-01 | Windows update script unquoted service name | Low | 3 |
| LOW-02 | Unconditional misleading startup message | Low | 3 |
| LOW-03 | `dev/null` accidental commit | Low | 1 |
| LOW-04 | `internal-only` unexplained file | Low | 3 |
| LOW-05 | `coverage` artifact committed | Low | 1 |
| LOW-06 | Config loaded but discarded in services CLI | Low | 3 |
| LOW-07 | `test-run/` directory not in gitignore | Low | 1 |
| LOW-08 | AI release note failure is silent | Low | 3 |

---

## Appendix B — Scope Clarification

The original audit request mentioned a frontend, Supabase Edge Functions, SQL migrations, RLS policies, and RPCs. **None of these components are present in this repository.** This repository contains exclusively the Go agent binary and its build/CI infrastructure.

The following requested audit areas were **not applicable** to this repository:

- Frontend architecture (React, hooks, components, services)
- Supabase RLS implementation
- SQL migrations
- Database triggers and functions
- Seed data
- Edge function source code
- RBAC implementation in the backend

These components must be audited separately against the SentinelOps frontend/backend repository (if one exists separately).

---

*Report generated by Kiro AI — July 27, 2026*  
*No code was modified during this audit. All findings are read-only observations.*
