# SentinelGo Testing Guide

Tests are **co-located with the code they exercise** — each package owns its
`*_test.go` files (idiomatic Go). There is no longer a monolithic `tests/`
package. This guide covers how the suite is organized and how to run it.

## Running tests

```bash
go test -short ./...          # fast, offline, deterministic — the default gate
go test ./...                 # full suite, including slow OS/integration tests
make test                     # full suite with coverage report
make pre-release              # quality gate (uses go test -short ./...)
```

`-short` is the contract: it must pass with **no network access** and complete
quickly on every OS. Use it as the default while developing.

## How tests are organized

- **Co-located, external test packages.** Tests live next to their package as
  `package <pkg>_test` (e.g. `internal/service/authService_test.go` is
  `package service_test`). Pure-logic tests that need package internals use the
  in-package form.
- **Platform-specific tests use build tags / filename suffixes.** A
  `_linux_test.go` / `_darwin_test.go` / `_windows_test.go` file only compiles
  and runs on that OS. OS-agnostic logic (parsers, mappers) is factored into
  untagged files so it can be tested on any host — see
  `internal/auditlogs/collector/collector_parse_test.go`.
- **Network/Supabase is mocked, never real.** HTTP boundaries are tested with
  `httptest.NewServer` and an injected base URL (services accept the URL). No
  test in the default run dials a real host.
- **Slow / integration tests are gated behind `testing.Short()`.** Anything that
  shells out to the OS (`osinfo.Collect()`), starts the full agent, or performs
  real network I/O skips under `-short`. They still run in the full
  `go test ./...`.
- **Updater network tests are opt-in.** They require
  `SENTINELGO_UPDATER_NETWORK_TESTS=1` (and are skipped in `-short`) because the
  update path is destructive (downloads and replaces the binary).

## Enforcement (pre-release gate)

`make pre-release` runs:
- `gofmt` + `go vet` + `golangci-lint`
- `make check-no-cgo` — fails if any `import "C"` exists (see CLAUDE.md)
- a cross-platform build of every `GOOS/GOARCH` with `CGO_ENABLED=0`
- `go test -short ./...` — must pass offline

## Adding a test

Put it in the package it tests, as `package <pkg>_test`. If it needs the
network, mock it with `httptest`; if it shells out to the OS or needs real
services, gate the slow path behind `if testing.Short() { t.Skip(...) }`.
