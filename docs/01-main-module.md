# SentinelGo — Main Module (`cmd/sentinelgo`)

The CLI entry point. Parses flags, then dispatches to one of the
subcommand handlers in this package, or, for `-run`, hands off to
`internal/main_integration.go` which starts the long-running agent
process.

> **See also:** full architecture and runtime flow in
> [`docs/08-project-overview.md`](08-project-overview.md). The CLI
> surface (every flag and subcommand, with examples) is the canonical
> reference in
> [`docs/agent-commands-guide.md`](agent-commands-guide.md).

## File layout

| File             | Role                                                              |
| ---------------- | ----------------------------------------------------------------- |
| `main.go`        | `func main()` — loads config, calls `processCommand(arg, cfg)`. |
| `flags.go`       | Defines the 9 supported flags (see below).                        |
| `commands.go`    | Subcommand handlers: `install`, `uninstall`, `status`, `forceFreshInstall`, `scheduledTaskMode`. |
| `process.go`     | The `processCommand(arg, cfg)` dispatcher and the `-run` / `-console` / `-service-mode` dev paths. |
| `service.go`     | kardianos service install / uninstall (cross-OS, build-tagged).   |
| `launchd.go`     | macOS-specific launchd plist helpers (`//go:build darwin`).       |
| `version.go`     | `Version`, `Commit`, `BuildDate` variables stamped at build time. |
| `software.go`    | Read-only software inventory CLI subcommand.                      |
| `tasks.go`       | Task listing / inspection CLI subcommand.                         |

## Supported flags

Nine flags total. The last three are dev-only and not used by the
installed service.

| Flag                          | Purpose                                                                                  |
| ----------------------------- | ---------------------------------------------------------------------------------------- |
| `-config <path>`              | Override the config file path (default is OS-specific, see [`docs/02`](02-config-module.md)). |
| `-version`                    | Print version info and exit.                                                             |
| `-install`                    | Install the OS service (launchd / systemd / Windows service).                            |
| `-uninstall`                  | Uninstall the OS service.                                                                |
| `-run`                        | Run the agent in the foreground (used by the service unit).                              |
| `-status`                     | Print whether the service is installed and running.                                      |
| `-force-fresh-install`        | Re-run the installer with a fresh agent UUID (testing).                                  |
| `-scheduled-task-mode`        | Windows-only — run the agent under a scheduled task instead of a service.               |
| `-console` / `-service-mode`  | Dev-only — run the agent interactively or simulate a service start.                      |

## Dispatch flow

```
main()
  +-- cfg = initConfig()                 // config.LoadOrCreate
  +-- processCommand(arg, cfg)
        |
        +-- arg == ""                   -> print usage
        +-- arg == "install"            -> commands.install(cfg)
        +-- arg == "uninstall"          -> commands.uninstall(cfg)
        +-- arg == "status"             -> commands.status(cfg)
        +-- arg == "version"            -> print version
        +-- arg == "force-fresh-install"-> commands.forceFreshInstall(cfg)
        +-- arg == "scheduled-task-mode"-> commands.scheduledTaskMode(cfg)   // Windows
        +-- arg == "run"                -> main_integration.New(cfg).Start() // blocks
        +-- arg == "console" | "service-mode" -> dev paths (see process.go)
```

`-run` is the only path that starts the full agent. The rest are
short-lived CLI operations. The 7-step agent startup sequence inside
`MainIntegration.Start()` is documented in
[`docs/08-project-overview.md`](08-project-overview.md#4-runtime-execution-flow).

## Imports of note

`cmd/sentinelgo/main.go` imports the two packages that own the agent's
runtime data:

- `agent "sentinelgo/internal/service/agent"` — the periodic
  agent-info upload service (see [`docs/06`](06-service-module.md)).
- `"sentinelgo/internal/agentinfo"` — the in-memory struct that
  reconciles host facts (OS, version, agent UUID) before upload.

`cmd/sentinelgo` does **not** import any `internal/heartbeat`,
`internal/constants`, or `cmd/auditlogs` package — references to those
in older revisions of this document are stale and should be ignored.

## Building

Builds are driven by the root `Makefile`:

- `make build` — local build for the host OS.
- `make build-all` — cross-compile for linux / darwin / windows (amd64 + arm64).
- `make release` — full release pipeline (see [`RELEASE_PROCESS.md`](../RELEASE_PROCESS.md)).

The version string baked into `version.go` comes from the most recent
git tag (e.g. `v1.4.2`) and is also written to the on-disk config's
`CurrentVersion` field, where it can be overridden by setting the
`SENTINELGO_VERSION` env var before first launch.
