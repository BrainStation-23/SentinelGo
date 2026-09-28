# Updater Module Documentation

> **Canonical references:** runtime fit and architecture —
> [`docs/08-project-overview.md`](08-project-overview.md). Config knobs
> (`auto_update`, `auto_update_interval`, `current_version`) —
> [`docs/02-config-module.md`](02-config-module.md). Release build/sign
> pipeline — [`RELEASE_PROCESS.md`](../RELEASE_PROCESS.md) and
> `.github/workflows/release.yml`.

## Overview

The updater (`internal/updater/`) installs newer SentinelGo binaries
automatically. Release **discovery and download** go through Supabase
(RPC + Storage). **GitHub Actions** only builds, ed25519-signs, and
publishes release assets; the running agent does **not** call the
GitHub Releases API.

Package layout:

| File | Role |
|------|------|
| `checker.go` | Discover latest release, compare versions, orchestrate apply, startup check |
| `downloader.go` | Authenticated Storage download, SHA256 + ed25519 verify |
| `installer.go` | Backup, atomic replace, OS-specific restart |
| `version.go` | Semver parse / strictly-newer comparison |
| `pubkey.go` | Embedded ed25519 public key (matches CI `SENTINELGO_SIGNING_KEY`) |

## Triggers

All paths end at `CheckAndApply` / `CheckAndApplyWithRetry`:

1. **Startup** — if `auto_update` is true, `MainIntegration.maybeStartupUpdateCheck`
   runs `StartupUpdateCheck` asynchronously (connectivity probe, then update).
2. **Scheduler** — enabled `auto-update` task on `auto_update_interval`
   (default **1h**), with up to 5 minutes of jitter in `handleAutoUpdate`.
3. **Remote task** — MDM slug `agent-update`
   (`internal/service/task/native/agent_update.go`); requires root on Linux;
   writes restart context before calling the updater.

## Apply flow (`CheckAndApply`)

Order is deliberate (verify before replace; version not persisted before restart):

```
1. fetchLatestRelease  → RPC get_latest_agent_release(p_platform, p_arch)
2. Compare latest.Version to compiled-in config.Version (strictly newer only)
3. Require SHA256 in the RPC row (refuse otherwise)
4. createBackup        → <exe>.backup
5. downloadAndVerify   → Storage agent-releases/<asset> + <.sig>
                       → SHA256 match + ed25519.Verify(PublicKey)
6. atomicReplace       → Unix only (Windows stages .new for post-exit swap)
7. restart             → exit; launchd / systemd / SCM relaunches
```

Notes:

- Comparison uses **`config.Version`**, not a stale `cfg.CurrentVersion`.
  On load, `config.Load` sets `CurrentVersion = Version` so reporting matches
  the binary that is actually running.
- Downgrades and equal tags never apply. Unparseable versions (e.g. `"dev"`)
  skip the update.
- Fail closed: missing `.sig`, bad signature, or checksum mismatch aborts and
  cleans up the staged file / backup as appropriate.
- On Unix replace failure, `rollbackFromBackup` restores the previous binary.

## Release discovery

```go
// PostgREST: POST {SupabaseURL}/rest/v1/rpc/get_latest_agent_release
// Body: { "p_platform": runtime.GOOS, "p_arch": runtime.GOARCH }
// Auth: Authorization Bearer <agent JWT>, apikey <anon key>
```

`LatestRelease` fields used by the agent: `version`, `asset_path`, `sha256`
(plus metadata such as `published_at`, `asset_name`, `size`).

Empty RPC result → no release configured yet; skip quietly.

## Download and verify

Binaries and detached signatures live in Supabase Storage bucket
`agent-releases`:

- Binary URL: `{SupabaseURL}/storage/v1/object/agent-releases/{asset_path}`
- Signature: same path with `.sig` suffix (base64-encoded ed25519 signature)

Download streams to `<exe>.new` while hashing SHA256, then verifies the
signature against `PublicKey` in `pubkey.go`.

Asset naming (set by the release pipeline) still follows:

- `sentinelgo-linux-amd64` / `sentinelgo-linux-arm64`
- `sentinelgo-darwin-amd64` / `sentinelgo-darwin-arm64`
- `sentinelgo-windows-amd64.exe`

## Restart by platform

| Platform | After successful stage |
|----------|------------------------|
| Linux | Binary already replaced; `os.Exit(1)` → systemd `Restart=on-failure` |
| macOS | Binary replaced; ad-hoc re-codesign + `spctl --add`; `os.Exit(0)` → launchd KeepAlive |
| Windows | Running `.exe` is locked; write `sentinelgo_update.bat`, exit `0`; script moves `.new` into place and `sc start SentinelGo` |

## Retry

`CheckAndApplyWithRetry`: up to 3 attempts; backoff 5s → 10s → … capped at 5 min.

## Config

| Key | Default | Role |
|-----|---------|------|
| `auto_update` | `true` | Enables startup check + scheduler `auto-update` task |
| `auto_update_interval` | `1h` | Scheduler cadence (`GetAutoUpdateInterval`) |
| `current_version` | build-time `Version` | Overwritten on load from compiled-in version; used for inventory/logging |
| `supabase_url` / tokens | — | RPC + authenticated Storage download |

There are **no** `github_owner` / `github_repo` config fields. GitHub is only
the CI publisher.

## Security summary

- Authenticated RPC and Storage (agent JWT + anon key; bucket RLS).
- Integrity: SHA256 from the release manifest.
- Authenticity: ed25519 detached signature; public key embedded in the agent;
  private key is GitHub Actions secret `SENTINELGO_SIGNING_KEY`.
- Backup before replace; rollback on Unix replace failure.
- Staged Windows update script ACL-hardened via `winsec.SecurePath`.

## Related entry points

| Caller | Function |
|--------|----------|
| `internal/main_integration.go` | `StartupUpdateCheck` (async when `AutoUpdate`) |
| `internal/scheduler/scheduler.go` | `handleAutoUpdate` → `CheckAndApplyWithRetry` |
| `internal/service/task/native/agent_update.go` | remote `agent-update` task |
