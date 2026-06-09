# SentinelGo

A cross-platform Go system agent that reports device health, streams audit logs, runs remote commands, and self-updates. Runs as a Windows Service, systemd unit, or launchd job.

## What it does

- **System metrics heartbeat** — CPU, memory, disk, network, battery, disk encryption, local user accounts, OSQuery version, hostname/architecture/uptime, sent periodically to a Supabase backend.
- **Software inventory** — installed apps and versions, reconciled against the local SQLite store and synced via the `agent-software` Edge Function.
- **Audit log streaming** — Windows Event Log / Linux journald / macOS unified log events, batched and uploaded with at-least-once durability (SQLite checkpoint + exponential-backoff retry).
- **Task execution** — pulls pending commands from a Supabase task queue, downloads the script payload from a private `command-scripts` Storage bucket, runs it, reports the result.
- **Self-update** — daily check of GitHub Releases, atomic binary replace, graceful restart.
- **CLI** — install/uninstall the service, run in foreground, dump status, etc.

## Quick start

1. Grab a release for your OS/arch from [GitHub Releases](https://github.com/BrainStation-23/SentinelGo/releases/latest).
2. Drop it in the platform install location (`/opt/sentinelgo/` on Linux/macOS, `C:\sentinelgo\` on Windows).
3. Drop a `config.json` next to the binary — see [Configuration](#configuration) and the full reference in [`docs/02-config-module.md`](docs/02-config-module.md).
4. `./sentinelgo -install` (admin/root) to register the service, or `./sentinelgo -run` to run in the foreground.
5. For full per-OS steps, see [`installation-doc/INSTALLATION.md`](installation-doc/INSTALLATION.md).

## Build from source

```bash
make build                # dev build -> bin/sentinelgo[.exe]
make test                 # go test ./...
make verify-cross         # type-check every GOOS/GOARCH with CGO_ENABLED=0
make check-no-cgo         # fail if any `import "C"` is reintroduced
make pre-release          # quality gate + build
make release VERSION=vX.Y.Z
```

All builds are `CGO_ENABLED=0` static binaries, cross-compiled from a single host. Go 1.25+ required.

## Configuration

The agent reads a single JSON file. Default locations:

- Linux / macOS: `/opt/sentinelgo/.sentinelgo/config.json`
- Windows: `C:\sentinelgo\.sentinelgo\config.json`

Override the path with `-config <path>`. Selected fields:

```json
{
  "supabase_url": "https://<your-project>.supabase.co",
  "access_token": "<agent-jwt>",
  "update_interval": "5m",
  "github_owner": "BrainStation-23",
  "github_repo": "SentinelGo",
  "current_version": "v2.1.5",
  "auto_update": false,
  "software_sync_enabled": true,
  "audit_log_enabled": true,
  "task_execution_enabled": true
}
```

The full field reference lives in [`docs/02-config-module.md`](docs/02-config-module.md). The agent performs a one-time login at startup to obtain `access_token`; the JWT is auto-refreshed and persisted to the OS keychain — see [`docs/06-service-module.md`](docs/06-service-module.md).

## CLI

```bash
sentinelgo -install      # install as system service (admin/root required)
sentinelgo -uninstall    # remove the service
sentinelgo -run          # run in foreground (foreground mode for debugging)
sentinelgo -status       # service status (installed/running/version)
sentinelgo -version      # print version
sentinelgo -config PATH  # use a custom config file
```

The full flag reference is in [`docs/agent-commands-guide.md`](docs/agent-commands-guide.md).

## Architecture

The high-level architecture, runtime flow, and package layout live in [`docs/08-project-overview.md`](docs/08-project-overview.md). Read that first if you want to understand how the pieces fit together.

## Documentation

| Document | Covers |
|---|---|
| [`docs/08-project-overview.md`](docs/08-project-overview.md) | Canonical architecture, package layout, runtime flow |
| [`docs/01-main-module.md`](docs/01-main-module.md) | `cmd/sentinelgo` CLI, flag parsing, service entry point |
| [`docs/02-config-module.md`](docs/02-config-module.md) | Configuration schema, env-var overrides, validation |
| [`docs/04-lockfile-module.md`](docs/04-lockfile-module.md) | Single-instance lock keyed on agent UUID + version |
| [`docs/05-osinfo-module.md`](docs/05-osinfo-module.md) | Cross-platform hardware metrics |
| [`docs/06-service-module.md`](docs/06-service-module.md) | Service lifecycle, auth, kardianos interface |
| [`docs/07-updater-module.md`](docs/07-updater-module.md) | GitHub Releases check, atomic replace, restart |
| [`docs/audit-logs-architecture.md`](docs/audit-logs-architecture.md) | Audit log pipeline (collect → parse → queue → upload) |
| [`docs/agent-commands-guide.md`](docs/agent-commands-guide.md) | Full CLI command and flag reference |
| [`docs/agent-script-download.md`](docs/agent-script-download.md) | Task script download protocol |
| [`installation-doc/INSTALLATION.md`](installation-doc/INSTALLATION.md) | Per-OS install steps |

## Security and privacy

- All data is transmitted over HTTPS with a per-agent JWT.
- Local user account collection excludes system accounts and only captures usernames.
- Use Supabase Row Level Security (RLS) to gate access on the backend.
- The agent never embeds credentials in the binary; the JWT is obtained at runtime and rotated.

## License

MIT
