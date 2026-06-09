# Test Suite Redesign Plan

Status: **Implemented** — the monolithic `tests/` package has been removed and all
tests are co-located per package. See `docs/testing.md` for the current guide.
Date: 2026-06-05

## 1. Why

The current test suite has three structural problems that make it unreliable and
misleading:

1. **No mocking strategy for Supabase / network.** Three incompatible patterns
   coexist:
   - Proper `httptest` mocks with URL injection (`audit_log_send_test.go`,
     `software_upsert_basic_test.go`, `software_upsert_simple_test.go`) — the
     correct approach, and the production code already supports it (services take
     a base URL).
   - ~7 "integration" tests permanently disabled with
     `t.Skip("requires valid authentication tokens")`
     (`agent_service_test.go`, `audit_log_rpc_test.go`, `software_service_test.go`,
     parts of `audit_log_send_test.go`). These test nothing.
   - Real external calls — the updater tests hit live GitHub (now gated behind
     `SENTINELGO_UPDATER_NETWORK_TESTS=1` + `-short`).

2. **No platform isolation.** There are **zero build tags** across all 38 test
   files; everything lives in one flat `package tests` compiled and run on every
   OS. Linux-only logic (e.g. `ps aux` parsing) is "handled" with scattered,
   ad-hoc `runtime.GOOS` skips. The audit log collectors — which are
   per-OS (`_linux.go` / `_darwin.go` / `_windows.go`) — have **no tests at all**,
   and there is nowhere to put OS-specific collector tests.

3. **Monolithic external test package.** One black-box `tests/` directory separate
   from the code is the root cause of the above:
   - No seams to inject fakes → tests either hit the real thing or get skipped.
   - No platform co-location → can't have a Linux-only test file.
   - No per-package isolation → one slow test blocks everything (the `osinfo`
     shell-outs take 30s+ each and stall the whole suite).

## 2. Goals / Non-goals

**Goals**
- Default `go test ./...` is **offline, deterministic, fast**, and runs only the
  code valid for the host OS.
- Supabase and all network boundaries are **mocked**, never hit for real, in the
  default run.
- Platform-specific code is tested **on its own platform**, with the OS-agnostic
  logic (parsing, mapping) tested everywhere.
- Real-service / real-OS tests still exist but are **explicitly opt-in**.

**Non-goals**
- Changing production behavior. This is a test-layer redesign only.
- 100% coverage. We want meaningful, fast, honest tests — not a number.

## 3. Target design

### 3.1 Co-locate tests with the code they test
Replace the monolithic `tests/` directory with `_test.go` files next to each
package. This is idiomatic Go and unlocks everything else:
- Platform test files (`collector_linux_test.go` + `//go:build linux`) compile and
  run only on their OS, automatically.
- Internal logic can be unit-tested (`package foo` white-box) where appropriate.
- `go test ./internal/...` isolates failures per package; a slow `osinfo` test no
  longer blocks `config` tests.

### 3.2 Standardize Supabase/network mocking
Adopt the existing good pattern everywhere:
```go
server := httptest.NewServer(http.HandlerFunc(...))   // assert request, return canned response
defer server.Close()
svc := service.NewAuditLogService(cfg(server.URL, ...)) // inject the fake URL
```
- Every test that exercises a Supabase call uses an `httptest` server.
- **Delete or convert** every `t.Skip("requires valid authentication tokens")`
  test. A skipped test that needs real creds is not a test.
- No test in the default run may dial a real host.

### 3.3 Add seams for things that aren't HTTP
The new collectors shell out to `journalctl` / `log show`. Make that boundary
injectable so it can be faked on any OS:
```go
type linuxCollector struct {
    run func(ctx context.Context, name string, args ...string) ([]byte, error) // defaults to exec
}
```
Then:
- **OS-agnostic tests (run everywhere):** feed canned `journalctl -o json` /
  `log show` bytes to `parseJournalLine`, `journalString`, `macMessageTypeToSeverity`,
  `parseJournalTimestamp`, etc. and assert the resulting `RawLogEntry`. These are
  pure functions and need no OS.
- **OS-specific tests (build-tagged):** a `//go:build linux` test that injects a
  fake `run` returning recorded journal output and asserts `Collect()` end-to-end,
  plus an opt-in integration test that calls the real `journalctl`.

### 3.4 Split fast unit vs. opt-in integration
- Default: fast, offline, deterministic.
- Real network / real OS commands / real services: behind `//go:build integration`
  **or** an env-flag gate (the pattern already applied to the updater), and/or
  `testing.Short()` so `go test -short` always skips them.
- Fix the slow `osinfo` shell-outs the same way: gate the real-command path behind
  short-mode, and unit-test the parsing against canned command output.

## 4. Conventions (the rules going forward)

- Test files live next to the code under test, not in a central `tests/` dir.
- A test that needs the network uses `httptest`; if it can't, it's an integration
  test and must be gated (`//go:build integration` or env flag) — never silently
  skipped.
- Platform-specific tests use the `_linux_test.go` / `_darwin_test.go` /
  `_windows_test.go` suffix (or an explicit `//go:build` tag). OS-agnostic logic is
  factored into pure functions and tested without a build tag.
- `go test -short ./...` must pass with no network and complete quickly on every OS.

## 5. Migration plan (phased, reviewable)

Each phase is independently mergeable; the old `tests/` dir shrinks as packages
migrate.

1. **Pilot — `internal/auditlogs/collector`** (the package we just rewrote):
   add the `run` seam, write OS-agnostic parser tests + build-tagged collector
   tests + an opt-in real-OS integration test. This becomes the reference example.
2. **Services / network layer** (`service`, `logging`, `heartbeat`, audit log
   send/rpc/upsert): migrate to co-located `httptest`-backed tests; delete the
   skipped "needs auth token" tests.
3. **Config / lockfile / models / parser**: straightforward co-located unit tests.
4. **`osinfo` / `procinfo`**: factor parsing out of the shell-outs; unit-test
   parsing everywhere, gate real-command tests behind short-mode + per-OS tags.
5. **Delete `tests/`** once empty; update `Makefile`/`pre-release-check.sh` to run
   `go test ./...` (per-package) instead of `./tests/`.

## 6. Enforcement

- `make verify-cross` already compiles every `GOOS/GOARCH` with `CGO_ENABLED=0`.
- Add to the pre-release gate: `go test -short ./...` must pass offline (no network
  reachable) — catches any test that still dials out.
- Optionally run the suite under `GOOS` for the supported platforms in CI so
  build-tagged tests are at least compiled for each OS.

## 7. Risks / trade-offs

- **Effort:** touches ~38 files; done in phases to keep each review small.
- **Lost "integration" coverage:** the skipped tests provided none today; the
  opt-in integration tier preserves the *option* to run against real services
  deliberately.
- **Seams add a little indirection** (e.g. the `run` field), but that's the price
  of testable boundaries and is standard Go practice.
