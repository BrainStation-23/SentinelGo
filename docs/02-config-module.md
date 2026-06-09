# SentinelGo — Config Module (`internal/config`)

Single JSON file that holds every tunable the agent reads at startup.
Loaded by `config.Load(path)`, persisted by `Config.Save` /
`Config.SaveAtomic`, validated by `Config.ValidateConfiguration`.

> **See also:** the runtime flow that consumes this config in
> [`docs/08-project-overview.md`](08-project-overview.md). The CLI flag
> that points to it (`-config <path>`) is in
> [`docs/01-main-module.md`](01-main-module.md).

## File location

| OS            | Default path                                       |
| ------------- | -------------------------------------------------- |
| Windows       | `C:\SentinelGo\.sentinelgo\config.json`            |
| Linux         | `/opt/sentinelgo/.sentinelgo/config.json`          |
| macOS         | `/opt/sentinelgo/.sentinelgo/config.json`          |
| (fallback)    | `$HOME/.sentinelgo/config.json`                    |

Override with `-config <path>` on any subcommand. The file is written
with `0600` permissions (read/write for owner only). The parent
directory is created with `0750`.

## On-disk file format

A normal JSON object. The exact field set depends on what was changed
at runtime — many fields are `omitempty` in code, so absent fields are
replaced with defaults on the next load.

```json
{
  "supabase_url":             "https://<your-project>.supabase.co",
  "device_id":                "ab12cd34ef567890",
  "agent_id":                 "0f1e2d3c4b5a6978",
  "agent_secret":             "<redacted>",
  "access_token":             "<jwt>",
  "refresh_token":            "<jwt>",

  "github_owner":             "BrainStation-23",
  "github_repo":              "SentinelGo",
  "current_version":          "v2.1.10",
  "auto_update":              true,
  "auto_update_interval":     "24h0m0s",

  "update_interval":          "5m0s",
  "agent_info_update_interval": "1h0m0s",
  "log_flush_interval":       "5m0s",

  "enable_task_polling":      true,
  "task_polling_interval":    "5m0s",
  "task_execution_interval":  "5m0s",
  "task_db_path":             "",

  "log_storage_enabled":      true,
  "audit_logs_enabled":       true,
  "software_sync_enabled":    true,
  "edge_function_url":        ""
}
```

`current_version` is the only field that is also baked into the binary
at build time via `-ldflags "-X sentinelgo/internal/config.Version=..."`
— see [Building](../01-main-module.md#building).

## Field reference

| JSON key                    | Go type     | Default                | Purpose                                                |
| --------------------------- | ----------- | ---------------------- | ------------------------------------------------------ |
| `supabase_url`              | `string`    | (none — required)      | Project URL the agent posts to. Validated as http(s).  |
| `device_id`                 | `string`    | 16 hex chars (random)  | Persistent host identifier. Generated on first run.    |
| `agent_id`                  | `string`    | 16 hex chars (random)  | Maps to the `agent_uuid` DB column. Generated on first run. |
| `agent_secret`              | `string`    | `""`                   | Shared secret used by `agent-login`.                   |
| `access_token`              | `string`    | `""`                   | JWT issued by `agent-login`.                           |
| `refresh_token`             | `string`    | `""`                   | JWT used to mint a new `access_token`.                 |
| `github_owner`              | `string`    | `"BrainStation-23"`    | Used by the updater.                                   |
| `github_repo`               | `string`    | `"SentinelGo"`         | Used by the updater.                                   |
| `current_version`           | `string`    | build-time `Version`   | Overridden by `SENTINELGO_VERSION` env var.            |
| `auto_update`               | `bool`      | `true`                 | Enables the daily release check (see [`docs/07`](07-updater-module.md)). |
| `auto_update_interval`      | `Duration`  | `"24h0m0s"`            | Cadence of the release check.                          |
| `update_interval`           | `Duration`  | `"5m0s"`               | Legacy software-sync interval (kept for back-compat).  |
| `agent_info_update_interval`| `Duration`  | `"1h0m0s"`             | How often `internal/service/agent` pushes inventory.   |
| `log_flush_interval`        | `Duration`  | `"5m0s"`               | Audit-log batch flush interval.                        |
| `enable_task_polling`       | `bool`      | `true`                 | Enables the Supabase task queue poller.                |
| `task_polling_interval`     | `Duration`  | `"5m0s"`               | Task queue poll cadence.                               |
| `task_execution_interval`   | `Duration`  | `"5m0s"`               | Cadence of the task executor sweep.                    |
| `task_db_path`              | `string`    | `""`                   | Override the SQLite task-store path (testing only).    |
| `log_storage_enabled`       | `bool`      | `true`                 | Enables local audit-log persistence.                   |
| `audit_logs_enabled`        | `bool`      | `true`                 | Enables the audit-log upload service.                  |
| `software_sync_enabled`     | `bool`      | `true`                 | Enables software-inventory upload.                     |
| `edge_function_url`         | `string`    | `""`                   | Optional override for the `agent-software` Edge Fn URL. |

> **Note on default-vs-comment drift in source.** The Go struct
> comments next to `AutoUpdate` and `EnableTaskPolling` say "Disabled
> by default for safety", but the actual code initialises both to
> `true`. The doc table reflects the **runtime** default (the code).
> A future PR should either flip the defaults to `false` or fix the
> comments.

## Duration fields

Any `Duration` field accepts either a string (`"5m"`, `"24h"`,
`"1h30m"`) or a raw number of nanoseconds on the way in. On the way
out, durations are always serialised as strings. `time.ParseDuration`
is used for the string form, so the usual Go duration units apply
(`ns`, `us`, `ms`, `s`, `m`, `h`).

## Environment variable overrides

There is **no broad `SENTINELGO_*` env-var layer.** The only env var
the config package reads is `SENTINELGO_VERSION`, used in `init()` as
the fallback value for the `Version` package variable (which in turn
becomes `current_version` on first save):

```go
func init() {
    if Version == "" {
        Version = getEnvOrDefault("SENTINELGO_VERSION", "v2.1.10")
    }
}
```

This is meant for build pipelines that want to stamp a version into
the binary before `make release`. Everything else must live in the
JSON file.

## Validation

`Config.ValidateConfiguration()` (and its unexported twin
`validateConfig()`) returns an error if:

- `supabase_url` is empty, **or** does not parse as an http(s) URL with a host,
- `device_id` is empty,
- `update_interval`, `log_flush_interval`, or `task_polling_interval` resolves to `<= 0`.

`Load` does **not** call `validateConfig` — validation runs on `Save`
and on demand. `main_integration.Start()` invokes
`ValidateConfiguration` itself before the lock file is acquired (see
[`docs/08`](08-project-overview.md#4-runtime-execution-flow)).

## Persistence

Two methods:

- `Config.Save()` — writes the marshalled JSON directly with
  `os.WriteFile`. Simpler, but not crash-safe.
- `Config.SaveAtomic()` — writes to `<path>.tmp` and `os.Rename`s into
  place. This is what the rest of the codebase calls.

Both use `0600` permissions and `0750` for the parent directory. A
manual `os.Chmod` to `0600` is also exposed as
`Config.SecureConfigFile()` for callers that copied a file by other
means.

## What this doc does not cover

- The auth flow that *populates* `access_token` / `refresh_token` —
  see [`docs/06-service-module.md`](06-service-module.md).
- The on-disk `current_version` semantics relative to the updater —
  see [`docs/07-updater-module.md`](07-updater-module.md).
- The Supabase row layout these fields map to — see the project-level
  schema in `docs/PROJECT_CONTEXT.md` (Phase D pending).
