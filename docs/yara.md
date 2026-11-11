# Threat hunting (YARA) on the agent

SentinelGo can scan files on a device with YARA rules that admins publish in
the SentinelOps console, and report which files matched. This page covers the
agent side. How the backend serves rules, schedules and scans, and the console,
is in Compliance-OS `docs/yara.md`; the shared contract is #409.

**This is threat hunting, not an antivirus.** The agent finds files that rules
describe and reports identifiers, hashes and paths. It doesn't block, delete
or quarantine anything, and it doesn't replace Defender, XProtect or an EDR.

## How a scan works

1. **Rules.** The `yara-ruleset-sync` task polls `agent_get_yara_ruleset`
   every 15 minutes. Rule sources are downloaded from Storage, rejected unless
   their size and SHA-256 match the bundle, and compiled in a sandboxed scan
   worker. The last good rules stay in force through any failure and are
   cached in `yara/` next to `config.json`, so scans work offline. Rules using
   modules the engine doesn't support (`import "pe"`) are skipped one by one
   and listed in the status; the rest of the ruleset still runs.
2. **When.** Each schedule in the bundle runs every `every_hours`, at an
   offset within `jitter_minutes` derived from the agent id and schedule id:
   the same on every restart, different on every device, so a fleet doesn't
   start at once. A new schedule first runs at that offset after the agent
   sees it. Admins can also start a scan from the console (`yara-scan` task,
   below).
3. **What.** The scope is a preset or a folder list:

   | Preset   | Folders                                                                                                                                                                                                                       |
   | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
   | `quick`  | Windows: each user's Downloads, Desktop, `AppData\Local\Temp`, Startup folder; `%PUBLIC%`, `%ProgramData%`, `%SystemRoot%\Temp`. macOS: each user's Downloads, Desktop, `Library/LaunchAgents`; `/private/tmp`, `/private/var/folders`, `/Library/LaunchAgents`, `/Library/LaunchDaemons`. Linux: each user's Downloads, `.config/autostart`; `/tmp`, `/var/tmp`, `/dev/shm`, `/etc/systemd/system`, `/etc/cron*`, `/root` |
   | `full`   | Windows: every fixed local drive. macOS: the data volume (`/System/Volumes/Data`). Linux: `/`                                                                                                                                 |
   | `custom` | The folders the schedule or scan lists for this OS. None for this OS means the device isn't scanned                                                                                                                           |

   Folders listed for a `quick` or `full` scan replace the defaults.
4. **Listing.** The walk never follows symlinks, junctions or mount points and
   never reads files itself. It skips: the agent's own folders, other security
   products' quarantine and definition folders, `/proc`, `/sys`, `/dev`, swap
   and hibernation files, the bundle's exclusions, network shares and
   removable drives (unless the limits include them), files over
   `max_file_bytes`, cloud placeholders whose content isn't on the device
   (reading would download them), and, for scheduled scans, files unchanged
   since the last scan with the same rules (the skip cache).
5. **Scanning.** Each file is opened by the service (checking it is still the
   file listed) and its descriptor handed to a sandboxed scan worker, which
   reads it once to hash it and match it. Workers run with no network and no
   access to anything else: an AppContainer and job object on Windows, a
   `sandbox_init` profile on macOS, a dedicated account with seccomp and no
   new privileges on Linux. A worker that takes longer than
   `per_file_timeout_ms` is killed and the file skipped. The YARA pool has one
   worker, separate from file DLP's, so a full scan never delays DLP.
6. **Reporting.** Each match becomes a `match` event: rule, ruleset and
   revision, string identifiers (`$s1`), the file's SHA-256, size, mtime,
   owner and path (or only a hash of the path and the extension in hashed
   path mode). Each scan ends with a `scan_summary` event. Events go to an
   on-disk queue (`sentinelgo_yara.db`) and are uploaded every minute by the
   `yara-event-sync` task; an offline device sends them when it is back. At
   most 5,000 match events per scan; scheduled scans don't report a match
   (same file, path, rule and revision) already reported.

## On-write scanning

With contract v1.1 (#418) the bundle can turn on `on_write`. Files written or
renamed into watched folders are then scanned as soon as they have been quiet
for 2 seconds, so a dropped tool is found in seconds instead of at the next
scheduled scan. It is detection only: nothing waits on a scan and nothing is
blocked.

- **Folders.** The bundle's `on_write.paths` for this OS (same syntax as
  schedules), or, when the list is empty, the on-write defaults: each user's
  Downloads, Desktop, temp and startup folders (Windows), Downloads, Desktop
  and `Library/LaunchAgents` (macOS), Downloads and `.config/autostart`
  (Linux), and the system's temp and autostart folders (`%PUBLIC%`, the
  common StartUp folder, `%SystemRoot%\Temp`; `/private/tmp`,
  `/Library/LaunchAgents`, `/Library/LaunchDaemons`; `/tmp`, `/var/tmp`,
  `/dev/shm`, `/etc/systemd/system`, `/etc/cron*`). These are the `quick`
  folders minus those that change all the time (`%ProgramData%`,
  `/private/var/folders`, `/root`). New user folders are picked up within a
  minute. `on_write.exclusions` and the built-in exclusions apply, and so do
  the network and removable drive limits.
- **Notifications.** The ones file DLP already uses, with no driver.
  Linux: fanotify `FAN_CLOSE_WRITE` on the folders' mounts, and
  `FAN_MOVED_TO` on their file systems where the kernel reports names (5.9 and
  later), so a file moved in from elsewhere on the same disk is seen too.
  Windows: `ReadDirectoryChangesW` on each folder. macOS: an FSEvents stream
  per folder. The agent's own writes are ignored.
- **Bursts.** A file is scanned when it has been quiet for 2 seconds, or a
  minute after its first change if it keeps changing. Each file waits once
  however many notifications it gets. At most 16,384 files wait at once. Past
  that, new ones are dropped and counted, and the next scheduled scan covers
  them. When the OS drops notifications that is counted too.
- **Sharing the worker.** On-write scans use the YARA worker at a priority
  below on-demand scans (while one runs, on-write gets one file a second) and
  above scheduled scans. They run within the bundle's `max_cpu_percent`, which
  counts on-write and scan time together, and use `max_file_bytes`,
  `per_file_timeout_ms` and the skip cache. `max_files_per_scan`,
  `max_scan_minutes` and `skip_on_battery` don't apply.
- **Reporting.** Matches carry `trigger: on_write` and are de-duplicated like
  a scheduled scan's. They are grouped into windows of up to 24 hours, and
  each window ends (after 24 hours, or when the service stops) with one
  `scan_summary` (`trigger: on_write`, `preset: custom`), unless nothing
  happened in it. On-write windows don't replace the status's last scan.
- The agent advertises `yara_on_write_v1`; the backend sends an enabled
  `on_write` only to agents that report it.

## One scan at a time

- An on-demand scan stops a running scheduled scan. The scheduled scan is
  checkpointed and continues, under the same scan id, once the on-demand one
  has finished.
- A second on-demand scan while one runs doesn't start: the task answers
  `busy` with the running scan's id in `running_scan_id`.
- `yara-scan-cancel` stops whatever scan runs; it ends as `cancelled`.
- Threat hunting turned off (org switch, ring, `yara_enabled`) stops the scan
  (`cancelled`) and deletes the compiled rules. The event queue is kept.
- When the service stops, a scheduled scan is checkpointed and continues after
  the restart if its schedule is still due; an on-demand scan ends as
  `cancelled`.
- A scan that reaches `max_scan_minutes` or `max_files_per_scan` ends as
  `partial`; the schedule's next scan continues from where it stopped.

## Native tasks

| Task               | Params                                               | Result (last line of the task note)                                                   |
| ------------------ | ---------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `yara-scan`        | `{scan_id, preset, paths, ruleset_ids, reason}` (§4) | `{"scan_id": "…", "state": "started"}`, or `"busy"` with `running_scan_id`             |
| `yara-scan-cancel` | none                                                 | `{"scan_id": "…", "state": "cancelled"}`, or `{"state": "idle"}` when nothing was running |

`yara-scan` answers as soon as the scan runs; the outcome arrives as the
`scan_summary` event. It fails, and nothing starts, for an unknown preset, a
`custom` scan without folders, folders that don't exist on the device, ruleset
ids the device doesn't have, or threat hunting off on the device. It uses the
server's `scan_id` as its own.

## Guardrails

All from the bundle's `limits`, with safe defaults for anything missing:

| Limit                    | Default | Effect                                                                    |
| ------------------------ | ------- | ------------------------------------------------------------------------- |
| `max_cpu_percent`        | 25      | The scan pauses while the worker uses more than this share of one core     |
| `skip_on_battery`        | true    | The scan pauses on battery and continues on AC                             |
| `max_file_bytes`         | 100 MB  | Larger files are skipped                                                  |
| `per_file_timeout_ms`    | 10,000  | Longer files are skipped (the worker is killed)                            |
| `max_files_per_scan`     | 500,000 | The scan ends as `partial`                                                |
| `max_scan_minutes`       | 240     | The scan ends as `partial` (time paused on battery counts)                |
| `include_network_mounts` | false   | Network shares are skipped                                                |
| `include_removable`      | false   | USB sticks and other removable drives are skipped                         |

The worker also runs at low CPU and I/O priority.

## Privacy

- Events carry identifiers, hashes and metadata only: never file content,
  matched bytes or excerpts. The server drops any other field.
- With path mode `hashed` the path never leaves the device: only the SHA-256
  of the lower-cased path and the extension.
- Logs name scans, rulesets and rules by id and count. They never contain rule
  text, matched bytes or file paths.
- The skip cache stores hashes of paths, not paths. The scan state file keeps
  the path a stopped scan continues from; it, the queue and the rules cache are
  readable by root/SYSTEM and Administrators only.

## Configuration

`yara_enabled` in `config.json` (default `true`) is the device's own switch.
`false` keeps scans and scan workers off whatever the console says; the agent
still polls and reports state `disabled`, which the console shows as
"disabled locally". With `true`, nothing is scanned until the server sends an
enabled bundle. Restart the service after changing it.

## macOS: Full Disk Access

Without Full Disk Access, macOS refuses the agent Desktop, Documents,
Downloads, Mail and other protected folders. Those folders are skipped (not
counted as errors) and the device reports state `tcc_denied`. Grant Full Disk
Access to `/opt/sentinelgo/sentinelgo` with the PPPC profile from the MDM
profile library (or System Settings → Privacy & Security → Full Disk Access).

## Files on the device

Next to `config.json` (`C:\sentinelgo\.sentinelgo\` on Windows,
`/opt/sentinelgo/.sentinelgo/` on macOS and Linux):

| File                     | What                                                  |
| ------------------------ | ----------------------------------------------------- |
| `yara/`                  | The cached bundle and rule sources                    |
| `sentinelgo_yara.db`     | Events awaiting upload; keys of matches reported      |
| `yara_scan_state.json`   | Each schedule's last run and where a scan continues   |
| `yara_skip.cache`        | Unchanged files to skip (hashes only)                 |
| `yara_status.json`       | The status `sentinelgo yara status` prints            |

`sentinelgo -uninstall` removes them, and the scan account on macOS and Linux.

## Troubleshooting

`sentinelgo yara status` (as Administrator or root; `-json` for JSON) prints
what the service last recorded: the local switch, the state, the applied
bundle version, each ruleset with its compiled and skipped rules (names and
reasons, never rule text), worker health, the running scan, the last scan,
each schedule's last and next run, on-write scanning (folders watched, files
waiting and dropped, the current window) and the event queue.

| State                | Meaning and what to do                                                                                   |
| -------------------- | -------------------------------------------------------------------------------------------------------- |
| `ok`                 | Rules applied, workers healthy                                                                           |
| `disabled`           | `yara_enabled` is false, or the server sends a disabled bundle (org switch off, outside the ring, agent too old) |
| `tcc_denied`         | macOS without Full Disk Access (above)                                                                   |
| `worker_unavailable` | Scan workers crashed repeatedly and were stopped; restart the service and check the log                  |
| `compile_failed`     | A ruleset didn't compile; the last good rules stay in force                                              |
| `download_failed`    | A rule source couldn't be downloaded or didn't match its SHA-256; the last good rules stay               |
| `too_large`, `unsupported_schema` | The bundle exceeds the contract's limits, or this agent is too old for it                   |

The service log has a line per scan start and end (`YARA: scan <id> completed:
… files scanned, … matches`), per bundle applied, and per upload.

## Coexistence with antivirus and EDR

The scan reads files the way a backup or search indexer does: opened
read-only by the service, read by a separate low-priority worker process
(`sentinelgo dlp-scan` / the same binary) with no network access. It never
writes to scanned files or changes their timestamps.

- **Microsoft Defender**: may scan the same files when the worker opens them,
  which costs time but is harmless. Defender quarantines files that match its
  own signatures (EICAR) before the agent can read them; test with the
  SentinelOps test marker rule instead. Customers who see the scan slow down
  can add a process exclusion for `C:\Program Files\SentinelGo\sentinelgo.exe`
  (or the install path); the agent's data folder can be excluded too.
- **CrowdStrike, SentinelOne and other EDRs**: a process reading many files is
  something they watch for (ransomware heuristics), but read-only access with
  no writes, renames or deletions doesn't match those patterns. If a
  customer's EDR flags the worker, add the agent binary as a trusted process
  or a performance exclusion, per the vendor's documentation.
- **macOS XProtect**: unaffected; its bundle is never scanned.

Exclusions only reduce the double scanning; the agent works without them.

## Performance

The pipeline benchmark (`go test ./internal/yara/scan -run '^$' -bench Scan
-benchmem`) runs the real engine in process over 200 random files (4-256 KB,
26 MB) with rulesets of 21 rules each (`nocase wide` text strings and hex
strings with wildcards):

| Rulesets | Throughput | Files/s | Allocated per file |
| -------- | ---------- | ------- | ------------------ |
| 1        | ~30 MB/s   | ~236    | ~1.2 MB            |
| 10       | ~4.5 MB/s  | ~35     | ~12 MB             |
| 50       | ~0.9 MB/s  | ~7      | ~60 MB             |

(One developer laptop, Windows, Go 1.26.) The cost grows with the number of
rulesets because the worker matches each ruleset in its own pass over the
file. Device measurements (quick and full scan duration, CPU, RSS of the
service and worker on a reference Windows laptop, Mac and Linux VM) are
collected on #417.
