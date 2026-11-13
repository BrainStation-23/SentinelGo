# File DLP: support runbook

For support and IT staff during the file DLP pilot (#430) and after it. It covers how to turn file DLP off on one device, where quarantined files go, how to give one back, and how to check what the device is doing. What file DLP covers on each platform is in [dlp-file-coverage.md](dlp-file-coverage.md).

Paths below use the default install. `<config dir>` is the folder holding `config.json`:

| OS | `<config dir>` |
|---|---|
| Windows | `C:\SentinelGo\.sentinelgo` |
| Linux, macOS | `/opt/sentinelgo/.sentinelgo` |

Everything here needs an administrator (Windows) or root (`sudo`, Linux and macOS): the folder is readable only by them and SYSTEM/root.

## Which switch to use

| Situation | Use | Reach | Undo |
|---|---|---|---|
| File DLP is stopping people working across the org | Console: Settings → Data protection → File DLP rollout → **Turn file DLP off now** | Online devices within a minute, others at their next policy poll. Clipboard DLP keeps running | Turn it on again in the console, for the pilot ring first |
| A policy blocks too much, but recording is fine | Console: put the device out of the blocking ring, or turn audit-only back on | Next policy poll | Undo it in the console |
| One device, now, whatever the server says (offline, or before the console change arrives) | The **emergency switch** `dlp-files-off` (below) | That device, within about 2 seconds, no restart | Delete the file |
| All DLP on one device, clipboard included | `"dlp_enabled": false` in `config.json`, then restart the service | That device, after the restart | Set it back to `true` and restart |

## The emergency switch: `dlp-files-off`

An empty file named `dlp-files-off` in `<config dir>` turns file DLP off on that device. The agent checks for it every 2 seconds, so no restart is needed. The server can't turn it back on.

Turn it on:

```powershell
# Windows (elevated PowerShell)
New-Item -ItemType File C:\SentinelGo\.sentinelgo\dlp-files-off
```

```sh
# Linux, macOS
sudo touch /opt/sentinelgo/.sentinelgo/dlp-files-off
```

Turn it off: delete the same file.

While it exists:

- The file hooks (fanotify on Linux, `ReadDirectoryChangesW` on Windows, FSEvents on macOS) stop judging files. Nothing is held, quarantined or deleted, and no file events are recorded.
- Files the session helpers hand over (Windows network shares and sync folders) are ignored.
- Removable drives the agent made read-only (`untrusted_devices`) become writable again.
- Process taint stops, and with it taint blocks (`network_control.taint_block`).
- Upload inspection stops redirecting uploads to the inspection proxy.
- The status reports the hook as `disabled_locally`, and each file channel as `unsupported:disabled_locally`, so the console shows the device as degraded rather than protected.

What it does **not** stop:

- **Blocked apps** (`network_control.blocked_apps`, Windows). Those WFP filters stay. Turn network controls off in the console, or stop the service (the filters live in a dynamic WFP session and disappear with the agent).
- Clipboard DLP. Use `dlp_enabled: false` for that.

## The local switch: `dlp_enabled`

`"dlp_enabled": false` in `config.json` turns all DLP off on the device, clipboard included, whatever the server says. It is read when the service starts, so restart it:

```powershell
# Windows
Restart-Service SentinelGo
```

```sh
# Linux
sudo systemctl restart sentinelgo
# macOS
sudo launchctl kickstart -k system/com.sentinelgo.agent
```

## Quarantine

With `on_close_violation: quarantine` and audit-only off, a file that violates a policy after it was written is copied into the quarantine folder, and only then removed from where it was written. In audit-only the file stays where it is, and the event says `would_have: quarantined`.

| | |
|---|---|
| Where | `<config dir>/dlp-quarantine` (Windows `C:\SentinelGo\.sentinelgo\dlp-quarantine`; Linux and macOS `/opt/sentinelgo/.sentinelgo/dlp-quarantine`) |
| Who can read it | root / SYSTEM and Administrators only (the folder is `0700` on Linux and macOS; on Windows it inherits the config folder's SYSTEM and Administrators-only permissions) |
| File names | `<UTC time>-<volume id>-<file id>-<original name>`, for example `20261113T080512Z-2049-1835012-q3-forecast.xlsx`. The original folder isn't kept |
| How long | 30 days. Older entries are removed when a new file arrives |
| Size | At most 1 GiB. When a file doesn't fit, it **isn't removed**. The event then says `monitored`, and the service log says "the quarantine folder is full" |

`on_close_violation: delete` removes the file without a copy. Nothing can be restored from a delete.

### Give a quarantined file back

1. **Find the event** in the console (DLP events, filter by device and channel). It has the time, the destination (drive label, share, sync folder), the file's SHA-256 and, depending on the evidence mode, its name.
2. **Find the file** in the quarantine folder by the time and name:

   ```powershell
   # Windows
   Get-ChildItem C:\SentinelGo\.sentinelgo\dlp-quarantine | Sort-Object LastWriteTime
   ```

   ```sh
   # Linux, macOS
   sudo ls -lt /opt/sentinelgo/.sentinelgo/dlp-quarantine
   ```

3. **Check that it's the right file**: its SHA-256 must equal the event's `file.sha256`.

   ```powershell
   Get-FileHash -Algorithm SHA256 C:\SentinelGo\.sentinelgo\dlp-quarantine\<name>
   ```

   ```sh
   sudo sha256sum /opt/sentinelgo/.sentinelgo/dlp-quarantine/<name>   # Linux
   sudo shasum -a 256 /opt/sentinelgo/.sentinelgo/dlp-quarantine/<name>   # macOS
   ```

4. **Stop it being quarantined again.** Copying it back to the same destination is judged like any other write. Either approve an exception for the file in the console (it is keyed by the file's hash, user and channel), trust the device or share, or give the file back somewhere file DLP doesn't watch, and let the user move it. That is not a removable drive, a share or a sync folder; OneDrive often syncs Documents and Desktop, so check before using them.
5. **Copy it out** as an administrator, drop the timestamp and ids prefix from the name, and give the user ownership of the copy (Windows: the copy belongs to Administrators; Linux and macOS: `sudo chown <user> <file>`).
6. **Delete the quarantined copy** once the user has the file.

## Check what a device is doing

On the device:

```sh
sentinelgo dlp status          # add -json for the same as JSON
```

Run it as administrator or with `sudo`. It reads only local state and works offline. For file DLP it shows:

- the cached bundle's files module: enabled, audit-only, `on_close_violation`, `untrusted_devices`;
- whether the emergency switch is on, and its path;
- how many files are in the quarantine folder, and their total size (never their names).

In the console, the device's DLP tab shows the status the agent last reported:

- each file channel's capability, `supported` or `unsupported:<reason>`;
- the hook's state (`running`, `disabled_locally`, `unavailable:<reason>`) and counters;
- the **pilot summary** `files.summary`: per file channel since the agent started, how many files were recorded, by action and by `would_have`, how many were quarantined or deleted, and which detectors matched. A newer `since` means the agent restarted and its totals started again from zero.

## During the pilot

- Keep `audit_only: true` on the pilot ring for the first two weeks, and read `would_have` per channel and detector before any enforcement (see #430 for the order: read-only removable drives first, then quarantine, never delete first).
- Before switching a policy to block, use the console's impact preview, and check its sample size.
- Every support case where file DLP got in the way: note the device, channel, detector and what was done (switch, exception, restore) on the pilot issue.
