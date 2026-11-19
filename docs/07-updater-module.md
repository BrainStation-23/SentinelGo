# Updater Module Documentation

> **Canonical references:** runtime fit and architecture —
> [`docs/08-project-overview.md`](08-project-overview.md). Config knobs
> (`auto_update`, `auto_update_interval`, `current_version`) —
> [`docs/02-config-module.md`](02-config-module.md). Release build/sign
> pipeline — [`RELEASE.md`](../RELEASE.md) and
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
| `version.go` | Semver parse / update decision (newer, or server-approved older) |
| `health.go` (+ `health_unix.go`, `health_windows.go`) | Update marker, health confirmation, the update watchdog and its rollback |
| `boot.go` (+ `boot_unix.go`, `boot_windows.go`) | The boot job that starts the watchdog after a reboot while an update is pending (#516) |
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
2. Compare latest.Version to compiled-in config.Version (newer, or older with allow_downgrade)
   → skip a version this device rolled back from, and wait while an earlier
     update still waits for its health check
3. Require SHA256 in the RPC row (refuse otherwise)
4. createBackup        → <exe>.backup
5. downloadAndVerify   → Storage agent-releases/<asset> + <.sig>
                       → SHA256 match + ed25519.Verify(PublicKey)
6. beginHealthWatch    → update_marker.json next to the config, and
                         sentinelgo-update-watchdog[.exe] (a copy of the old binary)
7. atomicReplace       → Unix only (Windows stages .new for post-exit swap)
8. spawnWatchdog       → `update-watchdog --marker …`, outside the service
   registerBoot        → boot job running the watchdog copy with --boot (#516)
9. restart             → exit; launchd / systemd / SCM relaunches
```

Notes:

- Comparison uses **`config.Version`**, not a stale `cfg.CurrentVersion`.
  On load, `config.Load` sets `CurrentVersion = Version` so reporting matches
  the binary that is actually running.
- Equal tags never apply. An older tag applies only when the RPC row has
  `allow_downgrade: true`, which the backend sets during an audited,
  admin-initiated rollback; the agent logs
  `Rolling back: vA -> vB (server-approved downgrade)`. The SHA-256 and
  signature checks are the same. A missing field (older backend) means false.
  Unparseable versions (e.g. `"dev"`) skip the update.
- Fail closed: missing `.sig`, bad signature, or checksum mismatch aborts and
  cleans up the staged file / backup as appropriate.
- On Unix replace failure, `rollbackFromBackup` restores the previous binary.

### Build flavor (#548)

Every release ships two builds: full (`sentinelgo-<os>-<arch>`) and
read-only (`sentinelgo-readonly-<os>-<arch>`, `-tags readonly`, #547). The
server decides per device which one it runs and returns that asset, with a
last column `flavor` (`full` | `readonly`):

- A `flavor` other than this binary's (`buildflavor.Flavor`) is installed at
  the **same version** too (`actionSwitch`, logged as `Switching build: …`),
  watched by the health check like an upgrade. Newer and older (with
  `allow_downgrade`) releases follow the usual rules and switch the build on
  the way. A server can move a device either way.
- `flavor` must be `full` or `readonly`, and the asset's name must be that
  build's (`sentinelgo-readonly-` prefix for read-only). A row that doesn't
  match is refused when it would be installed. A missing column (an older
  server) means this binary's own build, so a read-only agent offered the
  full asset is refused rather than turned back into a full agent.
- `update_marker.json` carries `to_flavor` and the health file `flavor`: the
  switch's new binary and the restored one have the same version, so only
  the build tells them apart. A switch that rolls back blocks that version
  (the rollback record), so it isn't retried in a loop.
- The agent reports the build it runs as `build_flavor` in every inventory.

## Health check and rollback (#503)

An upgrade keeps the backup until the new binary proves it works. A
server-approved downgrade (#505) isn't watched: it goes to an earlier release,
which may predate this check and could never confirm itself.

- **Marker.** `update_marker.json` (next to `config.json`, mode 0600) holds
  `from_version`, `to_version`, the binary, backup and health-file paths, the
  deadline (10 minutes) and `give_up_at` (24 hours). The old binary writes it
  once; afterwards it is only deleted, so the agent and the watchdog never
  write the same file. Versions are compared as semver (`2.1.6` = `v2.1.6`).
- **Watchdog.** Before restarting, the old binary copies itself to
  `sentinelgo-update-watchdog[.exe]` and starts it with
  `update-watchdog --marker <path>` so it survives the restart: as a
  transient systemd unit (`systemd-run`) on Linux, because systemd kills the
  agent's whole cgroup; in its own session on macOS, outside the process
  group launchd kills; detached (breaking away from a job when allowed) on
  Windows. It holds `update_watchdog.lock` (one watchdog per marker) and logs
  to `update_watchdog.log`. It starts before the binary is replaced; if it
  can't start, the update doesn't go ahead, because a new binary that can't
  start couldn't start a watchdog either.
- **New binary.** `StartHealthCheck` (first step of `MainIntegration.Start`)
  records each start (`attempts`, `booted_at`) in `update_health.json` and
  refreshes `alive_at` every 30 s. When no watchdog holds the lock, for example
  after a reboot, it starts one. Once the agent has signed in and an
  agent-info upload the server accepted (a payload it rejects with a 4xx
  doesn't count), `ConfirmHealthy` (from the `agent-info-update` task)
  deletes the marker, the health file, the backup and the watchdog copy, and
  the watchdog exits. If deleting the marker fails, the 30 s ticker retries
  it.
- **Confirm or roll back, never both.** The agent confirming and the watchdog
  rolling back each hold `update_transition.lock` (an OS file lock) and
  re-read the marker under it. Whoever gets it first ends the update; the
  other finds the marker gone (or another update's) and leaves the files
  alone.
- **Rollback.** The watchdog restores the backup when the new binary started
  more than 3 times, or when the deadline passed. The deadline is the
  marker's, or 10 minutes after the latest start if that is later. On Linux
  and macOS it replaces the file in place and restarts the service
  (`systemctl restart sentinelgo`,
  `launchctl kickstart -k system/com.sentinelgo.agent`, after re-registering
  with Gatekeeper). On Windows it stops the service with `sc stop`, waits for
  the binary to unlock, then runs `sc start`. It writes
  `update_rollback.json`. If that write fails (a full disk), it renames the
  marker to `update_rolledback_marker.json` instead, which needs no new
  space and still names the bad version; if even that fails, the marker
  stays, which holds updates back until `give_up_at`. The restored agent logs the rollback once, so it
  reaches the uploaded agent log, and the update checks skip that version
  until the server offers another one. The watchdog only restores
  `<exe>.backup` over `<exe>`, whatever the marker says.
- **Offline.** If the deadline passes while the new binary is alive but the
  watchdog can't reach the server either, the watchdog waits another
  10 minutes (in memory), for up to 24 hours. A marker older than that is
  stale and is removed.
- **Never installed.** If the binary still matches the backup (e.g. the
  Windows swap didn't run), the watchdog cleans up, records nothing, and
  starts the service in case it is down (`sc start`, `systemctl start`,
  `launchctl kickstart`, which leave a running service alone).
- **No stacking.** While an update waits for its health check, the agent
  doesn't start another one.
- **After a reboot (#516).** The spawned watchdog doesn't survive a reboot,
  and a new binary that fails before `StartHealthCheck` can't start one. So
  while an update is pending, a boot job starts the **watchdog copy** (never
  the new binary) with `update-watchdog --marker <path> --boot`:
  - Linux: `/etc/systemd/system/sentinelgo-update-watchdog.service`, enabled
    for `multi-user.target` (`ConditionPathExists` on the marker). None on a
    system without `systemctl`.
  - macOS: `/Library/LaunchDaemons/com.sentinelgo.update-watchdog.plist`
    with `RunAtLoad`. Registering only writes the file; launchd loads it at
    the next boot.
  - Windows: the scheduled task `\SentinelGo\UpdateWatchdog`, with a boot
    trigger, as SYSTEM, allowed on battery, a 2-day limit.

  It is registered next to the spawned watchdog (a failure is logged, not
  fatal) and again by the new binary at each start, so an update started by
  an older release is covered from the new binary's first start. It is
  removed when no update a watchdog could roll back is left (a valid marker
  whose backup exists): by the watchdog on its way out, by the confirmation,
  by an update that doesn't go ahead, and by the update checks retiring a
  stale marker. A rollback whose install failed keeps marker, backup and boot
  job, so the next boot tries again. The watchdog lock still allows only one
  watchdog: a boot-started one that finds another running exits and leaves
  the job to it.

  A boot-started watchdog gives the new binary a full 10 minutes from the
  boot to record a start, so a reboot near the deadline doesn't roll back an
  update that is still starting. If it hasn't recorded a start since the
  boot by then (it fails before its health check, however often the
  service manager restarts it), the watchdog rolls back with the reason
  "didn't start after the reboot".

## Release discovery

```go
// PostgREST: POST {SupabaseURL}/rest/v1/rpc/get_latest_agent_release
// Body: { "p_platform": runtime.GOOS, "p_arch": runtime.GOARCH }
// Auth: Authorization Bearer <agent JWT>, apikey <anon key>
```

`LatestRelease` fields used by the agent: `version`, `asset_path`, `sha256`,
`allow_downgrade`, `flavor` and `asset_name` (checked against `flavor`), plus
metadata such as `published_at` and `size`.

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
| macOS | Binary replaced; ad-hoc re-codesign unless it has a certificate signature that verifies (#352) + `spctl --add`; `os.Exit(0)` → launchd KeepAlive |
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
