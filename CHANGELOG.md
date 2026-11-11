# Changelog

All notable changes to SentinelGo are documented in this file. Each release's
section is published as its GitHub release notes.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Fixes for vulnerabilities are listed under **Security**, with their CVE or GHSA
identifier when one has been published.

To add an entry, see [Changelog entries](CONTRIBUTING.md#changelog-entries) in
the contributing guide. History before v2.1.17 is not recorded here.

## [Unreleased]

### Added

- Windows: local admin password rotation with escrow (#361). The agent rotates the built-in Administrator's password (found by SID, so a renamed one is found too), or a named local account's, on a schedule (every 30 days by default), after the account is used (8 hours after its last logon by default) and when the console asks (after a reveal, or Rotate now through the new `admin-password-rotate` task). Each password is generated on the device with `crypto/rand` (14–64 characters, Windows LAPS' complexity levels) and **escrowed to the backend's vault before it is set**, then confirmed. If the device is offline or the escrow fails, the password isn't changed, so the vault always has the one that works. A rotation interrupted by a crash is settled after the restart from the account's password-last-set time. The password is never logged, never written to disk and never sent anywhere but the escrow call. The password is set through `NetUserSetInfo`, never on a command line. The agent stands down and reports `managed_by` when Windows LAPS (CSP, Group Policy or local config) or legacy LAPS manages the device, and does nothing on domain controllers. It stays off until the console turns it on, and stays idle while the backend lacks the RPCs (`agent_get_admin_password_policy`, `agent_escrow_admin_password`, `agent_confirm_admin_password`, Compliance-OS#892). New `admin_password_rotation_enabled` setting in `config.json` (default `true`) turns it off on one device. New capability `admin_password_rotation_v1` (Windows). See `docs/admin-password-rotation.md`.
- Threat hunting with YARA rules (#404, #414, #416, #417). Admins publish YARA rules in the SentinelOps console and the agent scans files with them on a schedule or on demand, then reports which files matched: rule and ruleset, string identifiers (`$s1`), SHA-256, size, owner and path (or only a hash of the path, in hashed path mode). Never file content or matched bytes. It is threat hunting, not an antivirus: nothing is blocked or deleted. The agent now advertises `yara_scan_v1`, so the backend starts sending it rules once the organization turns threat hunting on (off by default).
  - Scans: each schedule runs every `every_hours`, at a per-device offset within `jitter_minutes` derived from the agent id (stable across restarts), so a fleet doesn't start at once. `quick` scans the folders malware usually lands in, `full` every local drive, `custom` the listed folders. The new `yara-scan` native task starts a scan from the console and answers at once with `{scan_id, state: started}`; the outcome arrives as a `scan_summary` event. `yara-scan-cancel` stops the running scan. One scan runs at a time: an on-demand scan pauses a scheduled one, which continues afterwards; a second on-demand scan answers `busy`. When the service stops, a scheduled scan is checkpointed and continues after the restart.
  - Guardrails: the scan pauses on battery and above the bundle's CPU budget (25% of one core by default), skips network and removable drives, cloud files that aren't on the device, files over 100 MB and unchanged files since the last scan, and stops after 240 minutes or 500,000 files (`partial`, continued next time). Files are read only by one sandboxed worker at background CPU and IO priority, separate from file DLP's.
  - Events wait in an on-disk queue and are uploaded every minute (`agent_enqueue_yara_events`), so an offline device sends them when it's back. The inventory carries a `yara` summary (state, rules applied, worker health, last scan, queued events).
  - New `yara_enabled` setting in `config.json` (default `true`): `false` keeps scans and workers off on that device whatever the console says, and the console shows it as disabled locally. New `sentinelgo yara status [-json]` shows the applied rules (names and skipped rules, never rule text), worker health, the running and last scan, the schedules' next runs and the event queue. `sentinelgo -uninstall` removes the YARA cache, state and queue. See `docs/yara.md`.
- YARA ruleset sync (#411, #412). The agent polls the new `agent_get_yara_ruleset` RPC every 15 minutes (the new `yara-ruleset-sync` task) and reports what it applied. Rule sources are downloaded from Storage and rejected unless their size and SHA-256 match the bundle, then compiled in a sandboxed scan worker (never in the service) before they replace the previous rules; if anything fails, the last good rules stay and the status says why (`download_failed`, `compile_failed`, `worker_unavailable`, ...). The rules are cached in `yara/` next to `config.json`, readable by root/SYSTEM and Administrators only, so they survive an offline reboot; a disabled ruleset deletes the cache. YARA scans run in their own pool of one sandboxed worker, separate from file DLP's, with a per-file timeout.
- Windows MSI for MDM and silent installs (#358). Each release now includes `sentinelgo-windows-amd64.msi`, one package for every device: `msiexec /i sentinelgo-windows-amd64.msi /qn SERVER_URL=… ANON_KEY=… ENROLLMENT_TOKEN=…` installs the agent in `C:\Program Files\SentinelGo` as the `SentinelGo` service and saves the single-use token, so the agent enrolls itself when the service first starts. The three properties are hidden from the installer log. Upgrades keep the agent's identity. Installed apps shows no Uninstall button for it; the MDM or an administrator removes it with `msiexec /x`, which leaves `C:\SentinelGo\.sentinelgo`. The release also includes `sentinelgo-installers.json`, with the MSI's ProductCode and SHA-256 for deployment tools. The MSI isn't Authenticode-signed yet.
- npm, PyPI and Composer package inventory (#421, global installs). The agent reports the packages installed globally for the machine and for each user: global `node_modules` (npm's default prefix, Homebrew, nvm, nvm-windows, fnm, Volta), Python `site-packages` (system, Homebrew, python.org, `pip install --user`, pyenv) and `composer global` installs. It only reads `package.json`, `METADATA`/`PKG-INFO` and `installed.json` files; it never runs npm, pip or composer, follows no symlinks and makes no network call while collecting. Packages go to the new `agent_enqueue_packages` RPC as full snapshots in parts of at most 5,000 packages, so the backend can match them against malicious-package advisories; when a location couldn't be read, the upload is a delta, so nothing the agent couldn't see is retired. It is off until the console turns it on: the agent polls `agent_get_package_settings` every 15 minutes and collects every 6 hours or when the settings change, and uploads an unchanged inventory only once a day. The new `sync-packages` task collects and uploads now. New capability `packages_v1`.
- Project lockfiles in the package inventory (#421), when the console turns on `project_scan`. The agent walks each user's home (or the configured `roots`) down to `max_depth` folders and reports the packages pinned by `package-lock.json` (v1–v3), `npm-shrinkwrap.json`, `yarn.lock` (classic and berry), `pnpm-lock.yaml` (v5–v9), `poetry.lock`, `uv.lock`, `Pipfile.lock`, pinned `requirements*.txt` and `composer.lock`, with the lockfile as the location. It never enters `node_modules`, `vendor`, virtual environments, hidden folders, `AppData` (Windows) or `~/Library` (macOS), follows no links, stays on the root's file system, skips network drives and never opens cloud files that aren't on the device (OneDrive/Dropbox placeholders, iCloud dataless files), so scanning triggers no download. Local, git and workspace dependencies are left out. A pass is limited to 3 minutes and 250,000 folder entries per run and continues where it stopped 15 minutes later; until the first pass finishes, uploads don't retire anything. The lockfile readers are small parsers of their own, with no YAML or TOML dependency.

### Fixed

- Windows: upload inspection no longer breaks whole websites (#451). Blocking direct connections to the inspected sites also blocked every other site on the same shared CDN addresses (github.com, Chrome updates), browsers before they picked up the proxy settings, and tools that ignore the system proxy (git, curl). A new policy setting, `modules.files.uploads.inspection.direct_block`, chooses how much is blocked: `quic` (the default, also for a missing or unknown value) blocks only UDP 443, so apps fall back to TCP and browsers take it through the proxy; `strict` keeps the old TCP and UDP block; `off` blocks nothing. `files.deep_inspection.direct_block` now also reports `mode` and the blocked `protocols`.
- Upload inspection: clients that require a certificate revocation check (curl and other Windows schannel/WinHTTP clients) no longer fail through the proxy with `CRYPT_E_NO_REVOCATION_CHECK` (#452). The certificates the proxy issues now name a revocation list the proxy serves itself at `http://127.0.0.1:<port>/ca.crl`: empty, signed by the device's inspection CA and renewed every few days.

### Security

- Built with Go 1.26.11, which fixes an HTTP/1 server crash in `net/http` (GO-2026-6859). The agent's local upload inspection proxy serves HTTP/1.
- First-boot enrollment errors are written to the service log with line breaks removed, so text in an enrollment server's error response can no longer add forged lines to the log (CodeQL alerts 224 and 225).

## [v4.0.8] - 2026-11-10

### Added

- Windows: file DLP on network shares opened by path, and the writing program for shares and sync folders (#428). Besides mapped drives, the session helper now watches the user's shares without a drive letter: live connections (`WNetOpenEnum`), remembered mappings (`HKCU\Network`) and shares Explorer has opened (`MountPoints2`), live ones first, at most 16, trusted shares skipped. A share is opened off the helper's loop, so a server that is gone can't stall it, and a share that can't be watched or goes away is tried again after a minute. With `process_taint` on, the ETW trace now also runs when only `file.network_share` or `file.cloud_sync` is on: opens on `\Device\Mup` paths are mapped to `\\server\share`, and sync folders are learned from the files the helpers hand over (never a whole profile). A handed-over file's event names the program that wrote it and uses its taint sources. The first file in a sync folder the service hasn't seen yet isn't attributed.
- Windows: upload inspection blocks direct connections to the inspected sites (#427). Apps that ignore the system proxy could upload to an intercepted site around the inspection; while the redirect is active and the files module isn't `audit_only`, the agent blocks direct TCP and UDP 443 to the addresses the exact `intercept` hosts resolve to, except from its own process (the proxy). Addresses follow the DNS TTL and stay blocked for 30 minutes after they were last seen; an address a `bypass` host shares is never blocked, and `*.` patterns can't be blocked by address. The rules are Windows Filtering Platform filters in a dynamic session, so they go with the redirect (proxy down, emergency switch, stop) and when the agent dies. `files.deep_inspection.direct_block` reports the state, the blocked address count and the hosts and patterns it couldn't cover. A site on a shared CDN address is blocked for direct connections too. New `internal/wfp`: the agent's own small WFP bindings (no driver, no new dependency).
- Linux: upload inspection redirect (#426). The proxy setting is per user on Linux, so each user's session helper points their desktop proxy at the inspection PAC script when the service asks: GNOME through `gsettings` (`org.gnome.system.proxy`), KDE Plasma 5 and 6 through `kwriteconfig` (`kioslaverc`, plus GSettings for GTK apps). It saves the user's previous values first and puts them back exactly when inspection stops, when the helper loses the service or exits, and after a crash (from a note in `~/.local/state`); values the user changed since are left alone. A user who already has a proxy keeps it (`unsupported:existing_proxy`). Each session's outcome is reported as its `upload_redirect` capability, and the device's redirect is `active` when at least one session applied it. Apps that ignore the desktop proxy aren't covered yet.
- Windows: file DLP on network shares and cloud sync folders (#330). They belong to the user's logon session, so the session helper watches the user's mapped network drives (`file.network_share`) and OneDrive, Dropbox, Box and iCloud Drive folders and a Google Drive volume (`file.cloud_sync`). It opens each written file as the user once the writer is done and hands the open handle to the service, which duplicates it out of the helper's process. The service decides from its own handle, not from anything the helper says: the share's server comes from the file's real path, a local file claimed to be on a share is refused, and the duplicate has no more access than the user's own, so remediation can only remove what the user could. Trusted shares are skipped. Deleting or quarantining a file in a sync folder also stops the sync client from uploading it, or removes the copy it already uploaded. Shares opened by their `\\server\share` path, without a mapped drive letter, are watched too (#428).
- Upload inspection in the service (#344 phase 2). When the policy turns on `modules.files.uploads.inspection` (proposed contract on Compliance-OS#532: `enabled`, `intercept` and `bypass` host lists; `audit_only` decides whether a violating upload is refused or only recorded), the agent runs the HTTPS inspection proxy on loopback, scans uploads in the sandboxed workers and serves a PAC script that sends only the listed destinations to it (bypass hosts never). On Windows it sets that script as the machine-wide proxy auto-config and adds the inspection CA to the local machine Root store; on macOS it sets each network service's automatic proxy, and the CA has to come from an MDM certificate payload (a service can't trust a root without one); on Linux the CA goes into the system bundle, and redirecting comes later. It fails open: the PAC script falls back to direct connections, a watchdog removes the redirect when the proxy stops answering or the emergency switch is on, the redirect is removed on stop, uninstall and after a crash, and it stands down (`unsupported:existing_proxy`) when the device already has a proxy configured. Turning inspection off removes the CA. `capabilities.file.upload` says whether uploads are really inspected, and `files.deep_inspection` reports the CA (fingerprint, dates, whether the system trusts it), the redirect and proxy state, and the counters.
- Windows: file DLP without a driver (#330). Removable drives (classified by the bus their disk is on, so USB hard disks count) are watched, and each file written there is scanned in the sandboxed workers once its writer has closed it. Windows has no way to hold a copy while the agent decides, so a `block` policy acts after the write: `on_close_violation` records, quarantines or deletes the file, deleting through the handle that was scanned so only that file can be removed. `untrusted_devices` makes drives no policy trusts read-only (a disk attribute that isn't kept across a re-plug, applied only when the volume can be locked, so a copy in progress is never cut off) and writable again when the setting changes, the device becomes trusted, the emergency switch is on or monitoring stops. Ejecting a watched drive isn't blocked: its watch closes when the user asks to remove it. `trusted_devices` matches the USB vendor, product and serial.
- Windows: with `process_taint` on, an ETW trace of file opens (it needs the service's admin rights) names the program that wrote a file to a drive, and a file that can't be judged on its own (unreadable, an archive) is judged by what that program opened in the user profiles before (#331). When the trace can't start, `capabilities.copy_correlation.process_taint` says why and scanning after the write keeps working.
- macOS: file DLP in the agent's daemon, without a system extension (#332). Removable drives and SMB, NFS, AFP and WebDAV shares are watched with FSEvents and files are scanned after the write, with the same `on_close_violation` and `untrusted_devices` (remounted read-only with diskutil) as Windows. `process_taint` and `os_copy_events` report `unsupported:needs_endpoint_security` until Endpoint Security, which needs Apple's entitlement.
- macOS: sandboxed scan workers (#332). As root each `sentinelgo dlp-scan` worker runs as a hidden `_sentinelgo-scan` account (or nobody), under the `pure-computation` sandbox profile where it works (no files by path, no network), else `no-network`, else resource limits only; `files.workers.sandbox` says which. The file reaches the worker as a descriptor; the worker never opens a path.

### Fixed

- File DLP: on a `block_override` block, the user's override or exception request is recorded after the block event it refers to, never before it.
- macOS file DLP: an integer beyond the 64-bit signed range in `diskutil`/`ioreg` output is no longer converted into a wrapped USB vendor or product id.
- Audit logs: the agent no longer resends batches the server already accepted (#436). Each upload chunk gets a `batch_id` when it is first formed and keeps it until the server confirms it, across retries and restarts, and each row carries its hash as `uid`; a server that recognises the batch (`duplicate: true`, BrainStation-23/Compliance-OS#828) counts as success. A chunk that fails is sent again on its own, never together with rows already confirmed. Rows uploaded in the last day aren't queued again, so an event the real-time subscription delivered and the next poll returned again goes once. Windows System events 35 and 24 were collected by two queries and are now collected once. `-collect-logs`, `-upload-logs`, `-logging-stats` and `-audit-logs` refuse to run while the agent is running, instead of starting a second pipeline on the same queue.
- Audit logs: a fresh install, or a missing or corrupt `checkpoints.json`, no longer ships years of history (#437). Windows channels and the Linux and macOS log files start at the server's retention window (3 days until the server sends one in the enqueue response, BrainStation-23/Compliance-OS#828), and rows dated outside it, or more than a day in the future, are dropped before they're queued and counted (`DroppedOutOfWindow`). A row whose timestamp can't be parsed keeps the collection time and is marked `event_data.timestamp_source: "collected"`.
- Audit logs: rows no longer exceed the server's 10 KB `event_data` limit and get rejected (#438). On Windows, `message` no longer repeats the event's named fields, which travel as their own keys. `event_data` is trimmed to 95% of the server's `max_event_data_bytes` (10,000 by default) by shortening the longest values, marked `truncated: true` with `original_bytes`; the row is never dropped. An upload body is now at most 256 KB instead of 900 KB.

## [v4.0.7] - 2026-11-06

### Added

- First-boot enrollment: on Windows the agent sends the PC's OMA-DM DeviceID and SMBIOS UUID with its enrollment token, so the backend can check a token issued to a Windows MDM enrollment against the PC that redeems it. When the backend's answer includes `mdm_host`, it is saved to `config.json` unless one is already set, so an agent installed by MDM can run `mdm-enroll`, `mdm-sync` and `mdm-unenroll` and reports `is_our_server` correctly (#398).

### Fixed

- macOS: an agent installed from a generic package now enrolls with the token from MDM managed preferences, including a profile delivered after the install. The LaunchDaemon starts the agent in service mode instead of `-run`, and `-run` itself now runs first-boot enrollment, so LaunchDaemons from older installs enroll too. A daemon that fails to start exits with its startup exit code, so launchd restarts it, instead of staying up with nothing running (#399).

## [v4.0.6] - 2026-11-05

### Added

- Windows: file DLP parses files in sandboxed worker processes, as on Linux (#328). Each `sentinelgo dlp-scan` worker starts in an AppContainer with no capabilities, so it has no network access (loopback included) and can open only what app packages may (system files) and its own executable; with a restricted copy of the agent's token: every privilege removed, Administrators deny-only, and only what Everyone, Users and Authenticated Users may open (system files, not users' profiles); at low integrity, so it can't write to normal locations; in a Job object that allows one process, caps memory at 1 GB, has no UI, and dies when the agent does. The file reaches the worker as a read-only handle the agent duplicates into it, so the worker never opens a path. Where a worker can't start in the AppContainer (it needs Windows 8 or later, and the agent adds an entry for the container to its executable's permissions), it starts without it, and where it can't start with the restricted token, at low integrity in its job; the status's `files.workers.sandbox` says which (`appcontainer,low_integrity,restricted_token,job`, `low_integrity,restricted_token,job` or `low_integrity,job`). A worker that hangs is killed at the scan deadline. The upload proxy (`sentinelgo dlp proxy`) on Windows now scans uploads in these workers instead of in its own process.
- File DLP reads two more formats (#327): Outlook messages (`.msg`), with the subject, sender, recipients and body (plain text, else the HTML body without its markup) and each attachment scanned as an entry, an attached message as a message; and Excel 5/95 workbooks. An S/MIME-encrypted message is `unscannable:encrypted`. A body kept only as compressed RTF (LZFu) is decompressed and read as RTF; a corrupt one is `truncated`.
- File DLP overrides and exception requests (#336 part 2; backend Compliance-OS#581). A policy whose action is `block_override` blocks like `block`, then asks the user, in a dialog in their own session, what to do: **Continue with a reason**, **Request an exception**, or **Cancel**. The dialog uses the desktop's own tool (a WinForms dialog through PowerShell on Windows, `osascript` on macOS, `zenity` or `kdialog` on Linux) and opens after the block, never while the file operation is held.
  - **Continue:** the file is allowed for that user and channel for 10 minutes, so copying it again works, and an `overridden` event records the reason (`override.justification`). A user may override at most `override_daily_limit` times a day (default 10; 0 turns overrides off).
  - **Request an exception:** the agent sends the policy, the blocked event, the file's hash and its name (by evidence mode) and the reason to `agent_request_dlp_exception`, for an admin to approve.
  - **Approved exceptions** in `modules.files.exceptions` let the matching file (or any file of the policy), for the matching user (or anyone), through until they expire.
  - The reason is free text and personal data: it is sent with the event or the request and never logged.
  - The Linux file hook reports capability `dlp_block_override_v1`, so the backend now sends `block_override` policies as such instead of downgrading them to `block`. Without a dialog tool, or with notifications off, the user gets the usual block notification.
- Linux: file DLP reports a document saved through a temporary file under the document's name (#337). Office suites and editors save by writing a temp file next to the document and renaming it onto it (LibreOffice `lu….tmp`, Office `~WRL….tmp`, GIO `.goutputstream-…`); such a file is now held for up to 2 seconds until its rename, so the event, the extension a policy matches and a quarantine see `plan.docx`, not the temp file. A temp file deleted before its rename is not reported (nothing of it is on the drive); one never renamed is judged under its own name. Nothing is skipped because of its name.
- Linux: file DLP can **block** copies to USB drives and network shares (#333, fail-safes #329). When a policy's action is `block` and the files module isn't audit-only, a copy program (`cp`, `mv`, `rsync`, `install`, `dd`, `tar` and the common file managers: Files/Nautilus, Nemo, Caja, Thunar, PCManFM, Dolphin, Konqueror, Krusader, Double Commander, Midnight Commander) that creates a file on a monitored drive or share is held while the agent scans the files it has open for reading; if one matches, the open fails with "Operation not permitted" and nothing is written. The event is `blocked`, with `correlation.method: open_file` and the source's hash and name (by evidence mode). Other programs, and files overwritten in place, are judged after the write as before (`on_close_violation`), so an editor that keeps an unrelated document open is never judged by it.
  - **It fails open.** Every held open gets exactly one answer; a timer allows it after `scan_timeout_ms` (at most 10 seconds); past 64 held opens, new ones are allowed at once; a decision that panics allows; stopping the agent allows everything held. The event loop never touches the file system, and a watchdog closes the permission group if the loop stalls anyway, which makes the kernel allow everything held; blocking then stays off, reported as `stopped:watchdog`, until the file hook restarts. The emergency switch (`dlp-files-off`) and audit-only turn it off.
  - Antivirus, indexers, thumbnailers and backup daemons are never held: only copy programs are judged, decided from `/proc` in the event loop. Backups to a USB drive with `rsync` are judged like any copy: list backup drives as trusted devices.
  - The DLP status's `files.blocking` reports its state and counters: `allowed`, `denied`, `timeouts`, `timeout_denied`, `overloaded`, `pending`.
  - **Cost**, measured on a 5.15 kernel: about 1.3 ms more per file a copy program creates (its source scanned in the sandboxed worker), about 0.15 ms per open by any other program on the drive.
- File DLP tells the user why (#336, part 1). When a file is blocked, removed after the write (`quarantine`/`delete`) or matches a `warn` policy, the user whose program did it gets a desktop notification with the policy's block message (detector names, never the matched values), the file name and the destination (the USB drive "KINGSTON"). Copying a folder gives one notification ("SentinelOps blocked 12 files"), and a file retried within a minute isn't counted again. Events gain `user_notified`: whether that user could be told (their session has a helper and notifications reach them). Overrides with a reason and exception requests come later.
- Notification readiness (#323; console Compliance-OS#623). The session helper checks whether a notification can reach its user and reports it as the session capability `notifications`: `supported`, `disabled:global`, `disabled:app`, `disabled:policy`, `dnd`, `unavailable:<reason>` or `unknown`. Windows reads the user's toast settings, Group Policy and the shell's quiet state (full-screen app, presentation mode); macOS the notification preferences for the app that posts them and a managed (MDM) setting; Linux `notify-send`, the session bus's notification server and GNOME/KDE Do Not Disturb. It is read at connect, every minute and just before each notification.
  - `notify-user` no longer reports "Shown" for a session where the system hides notifications: that session is listed as not shown, with why. Do Not Disturb counts as shown (kept in the notification center), with a note.
  - The inventory gains a top-level `sessions` (each helper's user, state and capabilities), so the console sees readiness on devices with DLP off too.
- Local administrator rights run natively, and a time-limited grant ends on the device even when it's offline (#388; backend Compliance-OS#715). The agent now handles the console's `local-admin-add` and `local-admin-remove` commands itself (older agents keep running the commands' scripts) and reports capability `local_admin_v1`. It behaves like the scripts: the Administrators group by SID on Windows (falling back to `net localgroup` for `AzureAD\` names), `admin` with `dseditgroup` on macOS, `sudo`/`wheel` with `gpasswd` on Linux; the same matching (local `bob` is never `CONTOSO\bob`); the same refusals (the built-in Administrator, system accounts, root, the agent's own account, the last enabled administrator); and the same one-line JSON result. Windows sign-out uses the Remote Desktop Services API rather than parsing `quser`.
  - **Offline expiry:** an add with `expires_at` is recorded in `local_admin_grants.json` in the config directory (locked down like `config.json`), and the service removes the rights at that time without the server, checking every 15 seconds and at start, so a deadline missed while the agent was down or the device asleep is handled at once. Setting the clock back doesn't extend a grant (the latest time seen and the process's monotonic clock both count), and a clock that reads earlier than the grant's start removes it. A failed removal is retried with backoff. A time-limited grant on someone who is already an administrator is refused, since its end would take away standing rights.
  - **Backup if the agent is stopped:** each grant also gets a one-shot OS task that runs `sentinelgo local-admin expire <grant_id>` at the end time: Task Scheduler as SYSTEM (run late if missed), a LaunchDaemon, or a systemd timer with `Persistent=true`. It's removed when the grant ends.
  - The inventory gains `admin_grants` (`grant_id`, `member`, `expires_at`, `state`: `active`/`removed`/`failed`, `removed_at`, `error`); removed grants are kept 7 days. `sentinelgo local-admin status` prints them.
  - The server doesn't send `expires_at` yet, so until it does the native commands add and remove like the scripts.
- File DLP: PDF files are now read (#327). The scan engine extracts the text of a PDF's pages, including objects packed in object streams (how Word and most tools save PDFs), Flate, ASCII85 and ASCIIHex streams, and fonts with a ToUnicode map (so text in embedded subset fonts, such as Calibri saved from Word, comes out as text). A damaged file still gives what it can, since objects are read in order without the cross-reference table. What it can't read is reported, never passed off as clean: an encrypted PDF is `unscannable:encrypted`, a PDF with no text at all (a scanned image; OCR is still out of scope) is `unscannable:unsupported_type`, and text in a font without a Unicode map, or a stream it can't decode, makes the result `truncated`. Decompression shares the archive limits (budget and compression ratio) against bombs. No new dependency.

### Fixed

- Inventory: a list the agent failed to collect (disks, GPUs, network adapters, peripherals, audio devices, printers, displays, local users) is now left out of the upload instead of being sent as `null`, so the console keeps the last good value (#387; console side Compliance-OS#641). A list that was collected and is empty is still sent as `[]`.

## [v4.0.5] - 2026-11-02

### Added

- File DLP copy correlation, part 1 (#334; backend Compliance-OS#570): the agent reads `modules.files.copy_correlation`. Unreadable settings fall back to the defaults, which keep today's behaviour, and are reported.
  - **What happens to a file found to violate a policy after it was written** (`on_close_violation`, Linux): `record` (the default), `quarantine` (moved to a root-only `dlp-quarantine` folder in the config directory, at most 1 GB, entries kept 30 days), or `delete`. It applies only where a policy's action is `block` (or `on_unscannable`/`on_timeout` say `block`); a `monitor` policy never touches a file. Before moving or deleting, the agent checks that the path still names the exact file it scanned, so a file swapped in meanwhile is left alone. The event says `quarantined` or `deleted`, or stays `monitored` if that failed.
  - **Audit-only records what it stopped:** the event's `would_have` is `quarantined`, `deleted`, or (for the upload proxy) `blocked`.
  - `scan_on_close: false` stops the Linux monitor.
  - The status reports what each method can do on this device in `capabilities.copy_correlation`. On Linux, `scan_on_close` is supported and `os_copy_events` is `unsupported:not_on_linux`; `untrusted_devices` and `process_taint` are supported too (below).
  - **Process taint** (`process_taint`, Linux, off by default): while a monitored drive or share is mounted, the agent remembers which files under `/home` each process opens (up to 32 per process, for `taint_window_seconds`, in memory; nothing is scanned at that point). When a file written to the drive can't be judged on its own (it's unreadable, or an archive), the agent checks the files its writer read just before (newest first, at most 8; reopened and checked to be the same file, then scanned like any file). If one matches, the event comes from it (`correlation: {method: taint, source_sha256, source_name}`, `verdict_source: correlation`), and the after-write action applies to the written file. A readable file that matches nothing is never judged by what its writer read earlier. Opens are watched by their own fanotify group, so a flood of them can't push out the drive's events. **Cost:** in a test with 100,000 opens while a drive was mounted, the workload took about 28% longer and the agent used about 5 µs of CPU per open, with no events lost.
  - **Untrusted USB drives** (`untrusted_devices`, Linux): with `read_only` or `block_writes`, a removable drive whose device neither the files module nor a removable-channel policy trusts is remounted read-only, so nothing can be written to it. Only that mount point changes, and its other flags (`nosuid`, `nodev`, `noexec`) are kept. One event per drive (`blocked`, `scan.status: not_scanned`, the device's ids), or `monitored` with `would_have: blocked` while audit-only. The agent makes the drive writable again when the setting goes back to `allow`, the device becomes trusted, the emergency switch is on, or monitoring stops; after a crash it stays read-only until plugged in again.
- File DLP uploads, phase 1 (#344): new `sentinelgo dlp proxy -hosts H1,H2`, a local HTTPS proxy for testing upload inspection by hand. A browser pointed at it, trusting the inspection CA it exports (`-ca-out`), has its uploads to the listed hosts (`*.example.com` for subdomains) decrypted and each uploaded file scanned with the cached policy's `file.upload` channel. A file that matches a `block` policy gets HTTP 403 with the policy's block message (unless the files module is audit-only), and the event names the destination host, never the URL. Everything else is tunnelled untouched. The inspection CA is generated on the device, and its key is a root-only file that never leaves it; host certificates live 24 hours. Real servers are verified against the system roots and verification is never skipped. The proxy listens on loopback only and never connects a client to a loopback, link-local (such as a cloud metadata service), unspecified or multicast address, checked on the address actually dialled. Upload bodies wait in a root-only spill directory that is emptied at start. Not yet run by the service: redirecting traffic to it (WFP, nftables, a Network Extension) comes in later phases.
- Linux: file DLP in audit-only mode for removable media and network shares (epic #324; #328, #329, #333). When the DLP policy enables `file.removable` or `file.network_share`, the agent watches USB sticks, SD cards and other removable drives (including LUKS-encrypted ones) and SMB, NFS and sshfs mounts. Each file written there is scanned, and a match is recorded as a `monitored` event with the file name (by evidence mode), type, size, hash, destination (volume label, USB vendor/product/serial, share host) and the program and user that wrote it. Nothing is blocked yet, whatever the policy's action.
  - **It can't hang the machine.** fanotify reports a file after it was written and closed, and the kernel never waits for the agent. If the agent falls behind, events are dropped and counted, never queued without limit.
  - **Files are parsed only in sandboxed workers** (`sentinelgo dlp-scan`), never in the root service. A worker runs as a dedicated `sentinelgo-scan` system account (no home, no shell; the service creates it the first time it starts workers, falls back to `nobody` if it can't, and `-uninstall` and `install.sh uninstall` remove it) in its own network namespace, with no new privileges, no file writes and no file access by path (Landlock). It reads only the file it is handed and returns findings, never text. A worker that doesn't answer in time is killed and replaced; repeated failures turn scanning off (`unsupported:scan_worker_failed`) instead of restarting forever.
  - Trusted devices and shares, and per-policy exceptions (apps, devices, shares), are honoured. A policy's `file_filters` narrow it to some file types (by extension or by detected type, so a renamed file still counts; each file inside an archive on its own) and sizes; a file outside every policy's size range isn't read at all. Filters the agent can't read are reported and the policy applies to every file. The same version of a file is scanned once per policy version. Files that can't be scanned, or time out, are recorded only when `on_unscannable`/`on_timeout` ask for it.
  - **Emergency switch:** creating `dlp-files-off` in the config directory (e.g. `/opt/sentinelgo/.sentinelgo/dlp-files-off`) stops file monitoring within seconds, without the backend; deleting it turns monitoring back on.
  - The DLP status reports each enabled file channel's capability (`supported`, `unsupported:fanotify_unavailable`, `unsupported:disabled_locally`, …) and a `files` block with the monitor's state and counters (scans, events, timeouts, dropped events, worker sandbox). Agents on other platforms report nothing new.
- File DLP groundwork (epic #324). Nothing is enforced on files yet, and nothing changes on devices. The DLP bundle now reads a `modules.files` section and file channels (`file.removable`, `file.network_share`, `file.upload`, `file.cloud_sync`) in the draft contract of #326. A `modules.files` the agent can't read is turned off and reported as a compile error, without affecting clipboard DLP. Defaults are audit-only and fail-open (`on_unscannable` and `on_timeout` are `allow` unless set to `block`), and a bundle with only file channels leaves DLP idle. New package `internal/dlp/filescan`, the scan engine (#327):
  - It detects a file's type from its content, not its extension.
  - It extracts text from plain text (UTF-8, UTF-16 with or without a byte order mark, Latin-1), CSV, JSON, XML, Word, Excel and PowerPoint files, OpenDocument and RTF. It also reads Microsoft sensitivity label names.
  - It scans the text in chunks that overlap, so a match across a chunk boundary is neither missed nor counted twice.
  - It opens zip archives entry by entry, with limits on depth, number of entries, total size and compression ratio against zip bombs.
  - Files it can't read are reported as `unscannable`, with a reason (`password_protected`, `rights_protected`, `too_large`, `unsupported_type`, `corrupt`), instead of being treated as clean. PDF, Excel 5/95 and Outlook `.msg` files have no text extractor yet and are reported as `unsupported_type`.
  - Legacy Office files are read too: Word, Excel and PowerPoint 97–2003 (`.doc`, `.xls` including number and formula cells, `.ppt`), each recognised as password-protected when it is. Files embedded in Office documents (other documents and OLE packages) are scanned as entries; an embedded object that can't be read, such as an equation, doesn't make the document unscannable.
  - A bounded verdict cache is keyed by the file's identity, size, times and policy version.

  File events gain `file`, `destination`, `process` and `scan` fields. In `masked` evidence mode only the file name is sent, never its path (#341). A test makes sure the scanner never logs, prints or opens files.
- macOS: the inventory has a new `mdm` block with the Mac's MDM state, so the console knows which Macs are enrolled, how, and in which MDM. It reports enrolled and user-approved, the enrollment type (`ade`, `profile`, `none` or `unknown`), supervision, the MDM server's host (never the full URL, which can carry tokens), whether that's this deployment's MDM (new optional config `mdm_host`), whether Apple Business Manager assigns the Mac to an MDM server, whether a Bootstrap Token is escrowed, and the serial number, hardware UUID and provisioning UDID (what Apple MDM identifies a Mac by; on Apple silicon it differs from the hardware UUID). The ADE lookup asks Apple's servers, so it runs only for Macs not enrolled through ADE, at most once a day. `profiles` now runs from `/usr/bin/profiles` instead of a PATH lookup. The agent reports capability `apple_mdm_state_v1` on macOS (#349).
- macOS: the `mdm` block also lists the settings an installed configuration profile enforces (`managed_settings`, e.g. `firewall`, `filevault`, `screen_lock`, plus the raw `profile_payload_types`), so the console can stop offering its own switches for settings MDM manages, and whether the agent has Full Disk Access (`grants.full_disk_access`, checked by opening the TCC database, which needs it even as root). Removing the MDM profile shows up as `enrolled: false` on the next inventory. New `sentinelgo mdm status [-json]` prints the device's MDM state for support (#353).
- New native task `mdm-enroll` (capability `mdm_enroll_v1`, macOS) gets a Mac enrolled in this deployment's MDM. A Mac that Apple Business Manager assigns to our MDM server re-enrolls through Automated Device Enrollment (`profiles renew -type enrollment`; macOS asks the user). Any other Mac gets its single-use enrollment profile from the backend (`agent_get_mdm_enrollment_profile`), which the console user's session helper opens in System Settings with a notification saying what to do, since macOS doesn't let an MDM profile be installed silently. A Mac enrolled in another MDM, or assigned to another MDM server in Apple Business Manager, is never touched. A user is shown the profile at most once a day unless the task sets `force`. The task waits up to two minutes for the enrollment to finish and then refreshes the inventory. Outcomes: `already_enrolled`, `ade_triggered`, `profile_presented`, `enrolled`; failures `other_mdm`, `no_console_user`, `ade_not_assigned`, `mdm_host_unknown`, `unsupported_os` (#350).
- First-boot enrollment: an agent installed from a generic package, with no `config.json`, registers itself with a single-use token instead of needing per-agent credentials baked into its installer. The token comes from `enrollment.json` next to where `config.json` goes (an installer can write it) or, on macOS, from MDM managed preferences (`com.sentinelgo.agent`: `EnrollmentToken`, `ServerURL`, `AnonKey`). The agent sends it with its serial number and provisioning UDID to the backend's `agent-enroll` function, saves the returned `agent_id` and `agent_secret` to `config.json` and deletes the used token file. On macOS, where the MDM can install the package before the profile with the token, the service stays up and retries until a token arrives; on other platforms a missing token fails startup as before. Installs that already have a `config.json` never enroll (#351).
- Windows: the inventory's `mdm` block now reports MDM state on Windows too: the edition and whether it can enroll in MDM (`eligible`, or `ineligible_reason` `home_edition`, `server` or `policy_blocked`, from `IsManagementRegistrationAllowed`), the active MDM enrollments (provider, server host, type `mdm_only`/`entra_auto`, state, UPN), whether one is this deployment's MDM or another one (`other_mdm`), and the OMA-DM device ID and SMBIOS UUID. Only enrollments with a discovery service URL count, since Windows keeps many non-MDM entries under `Enrollments` on every PC; `IsDeviceRegisteredWithManagement` confirms. Domain/Entra join stays in `identity_join`. The agent reports capability `windows_mdm_state_v1`, and `sentinelgo mdm status` shows the Windows fields (#355).
- Windows: the `mdm` block lists the settings an MDM enrollment enforces (`managed_settings`, e.g. `autoplay`, `screen_lock`, `removable_media`, `defender`, `software_update`, `bitlocker`, plus the raw `mdm_policy_areas`), so the console can switch those settings through the MDM instead of its own scripts. A policy counts only when its winning provider in `PolicyManager` is one of the device's MDM enrollments, so the provisioning policies every PC has don't. BitLocker recovery key escrow stays with the agent, since Windows can only back keys up to Entra ID or Active Directory; local admin password rotation is tracked in #361 (#359).
- Windows: new native task `mdm-sync` (capability `mdm_sync_v1`) starts an MDM session for this deployment's enrollment right away, so a queued MDM command doesn't wait for the device's next poll; it stands in for push notifications, which Windows MDM would otherwise need Microsoft's WNS for. It runs `deviceenroller.exe /o <enrollment> /c /b` (what the enrollment's own scheduled tasks run) and falls back to the enrollment's `PushLaunch` task. It only ever syncs our enrollment, never another MDM's, and coalesces repeated requests within 30 seconds (#357).
- Windows: `mdm-enroll` (capability `mdm_enroll_v1`) enrolls a PC in this deployment's MDM silently. The agent gets a single-use token from the backend (`agent_get_windows_enrollment`: discovery URL, UPN, access token) and calls `RegisterDeviceWithManagement` from the service, with no user involvement. If that fails, it opens the `ms-device-enrollment:` link in the console user's session (a new session-helper message, `open_url`, that opens only enrollment links), so they can finish in Settings. Home and Server editions, and PCs where policy blocks MDM, answer `ineligible`; a PC enrolled in another MDM is never touched. New task `mdm-unenroll` (capability `mdm_unenroll_v1`) removes this deployment's enrollment when the console asks; uninstalling the agent doesn't unenroll (#356).
- New `sentinelgo enroll -token TOKEN|- -server-url URL -anon-key KEY` saves a first-boot enrollment token for an agent installed from a generic package. Installers run it, e.g. a generic MSI's custom action with its `ENROLLMENT_TOKEN` and `SERVER_URL` properties, so the agent registers itself on its first start (#351). The token can be read from stdin, so it doesn't show in the process list; the file gets the same SYSTEM/Administrators-only (Windows) or 0600 permissions as `config.json`. An agent that's already configured ignores it (#358).
- Clipboard DLP policies can **warn**, a middle ground between monitor and block: the copy is left on the clipboard, and the user gets a notification that they copied sensitive data and that it was logged. The event is recorded as `warned`. When one copy matches several policies, block wins over warn, and warn over monitor. The notification text is the bundle's `modules.clipboard.warn_message` (default: "SentinelOps: you copied {{detector}}. This was allowed and logged.") and never includes the matched value. Copying the same text from the same app again doesn't warn again. The agent reports capability `dlp_warn_v1`; older agents skip a policy with an action they don't know, so the backend sends them `monitor` instead (#343).
- Desktop notifications show the SentinelGo icon. On Linux `notify-send` gets the icon installed at `/opt/sentinelgo/sentinelgo.png`; on macOS the icon is used when `terminal-notifier` is installed (otherwise notifications still go through `osascript`, without it); on Windows the icon is registered for SentinelGo's own app ID, and the binary carries the icon and version info. `install.sh` and `install.bat` copy the icon from the release bundle (#321).

### Fixed

- Windows: notifications were sent as Windows PowerShell, so they disappeared from the Action Center and were hidden when the user had turned PowerShell notifications off. They are now sent under SentinelGo's own app ID with the current toast template (#320).
- `notify-user` could list a user whose helper had shown the notification as unreached, and could race with the service stopping (#320).
- Linux: an sshd `Include` pattern that matched the file being read made the SSH settings collector read the same files over and over. Each file is now read once (#320).
- Windows: after a user signed out and back in, clipboard DLP and `notify-user` stopped working for them until the service restarted. The session showed `start_failed` and the clipboard `helper_not_connected`. All helpers shared one job object, and Windows binds a job to the session of its first process, so every helper for a later session was refused with "Access is denied". Each helper now gets its own job. A helper that can't start now reports why in the session's `last_error`, instead of only `start_failed`.

## [v4.0.4] - 2026-11-01

### Fixed

- Clipboard DLP never ran on Linux GNOME desktops with Wayland, the default on Ubuntu, Fedora and Debian. The clipboard showed `Not supported: no wl clipboard`, and installing `wl-clipboard` as that suggested would have made it open a window and grab focus 2.5 times a second, because GNOME has no data-control protocol. The agent now reads and blocks the clipboard over X11 itself, with no tools to install: on X11 sessions, and through XWayland on GNOME, KDE Plasma and wlroots desktops. It reacts to each copy as it happens instead of checking every 0.4 s, reconnects when XWayland restarts, and names the source app for X11 apps without `xdotool`. `wl-clipboard` is only used on Wayland without XWayland, and only when the compositor offers data-control (checked by asking the compositor, not by running `wl-paste`). The status reasons now point to what fixes them; see "Clipboard DLP Shows Not supported" in `installation-doc/INSTALLATION.md` (#315).
- A DLP channel that couldn't run when the policy arrived (a tool missing, the X server not up yet) only started with the next policy version or a helper restart. A channel that stopped with an error stayed stopped while the status said `running`. The session helper now checks again every minute, restarts a stopped channel with backoff, and reports each change to the console (#315).
- Linux: the session helper no longer runs twice in each GNOME or KDE session (one copy standing by). The autostart entry is now skipped where the systemd user unit starts the helper (#315).

## [v4.0.3] - 2026-10-30

### Fixed

- Clipboard DLP never started on macOS and Linux devices set up with `install.sh`: the installer (and, on Linux, the service install) made `/opt/sentinelgo` and the binary `0750`, but the per-user DLP helper runs as the signed-in user, who couldn't run it, so every session showed `start_failed` and the clipboard `helper_not_connected`. The installer now uses `0755` (root still owns both and is the only one who can write them; the config directory with the tokens is unchanged), and the service repairs existing installs on its own, adding read and execute for other users to the install directory and binary before it sets up the helpers. When a directory on the way is still closed to users, the session status says which one in `last_error` (#308).
- On macOS, a helper that refused the service's endpoint could be reported without `last_error`: it closed the connection at once, and macOS can't give the service the peer's credentials once the socket is disconnected, so the service couldn't tell whose helper it was. The helper now closes only its sending side and waits up to 2 seconds for the service to hang up, still sending nothing, so the service records `helper disconnected before hello`. This also fixes the intermittent `TestHelperExitsAfterUntrustedEndpoints` failure on macOS CI.

## [v4.0.2] - 2026-10-30

### Added

- Between full task polls, the agent asks every minute whether a task is queued for it (`agent_has_pending_tasks`, a read-only check) and fetches it at once. A command, an install or a DLP "Push now" now reaches the device within about a minute instead of at the next poll (5 minutes by default). Set `task_check_interval` in `config.json` to change it; a value at or above `task_polling_interval` turns it off. Against a server without the check, the agent keeps the regular poll and asks again an hour later.
- The DLP status now has a `state` field (`enforcing`, `no_policy`, `disabled_local`, `disabled_server`, `idle`), so a device that isn't enforcing no longer looks like one whose helper failed to start (#299).
- New native task `notify-user` (capability `desktop_notify_v1`): shows an admin's desktop notification to everyone signed in to the device, with a `title` (up to 64 characters), a `message` (up to 256) and a `level` (`info`, `warning` or `critical`). The task succeeds when at least one session shows it (`Shown to 2 sessions (alice, bob)`) and fails when nobody is signed in; the message isn't kept for later. To reach the user's desktop, the per-user session helper now runs whenever the agent runs, not only while DLP enforces; with DLP off it watches nothing and only shows notifications. Admin notifications aren't rate-limited like DLP's block notifications. The text is never logged (#301).

### Fixed

- Clipboard DLP could stay off on macOS after a self-update until the user logged out: a helper whose job launchd had loaded but wasn't running was taken as started, and a failed restart (`launchctl kickstart -k` timing out) wasn't retried as a restart. The agent now checks that the helper runs and starts it if not, keeps retrying a failed restart, and falls back to unloading and reloading the job when `kickstart -k` fails. On macOS and Linux, sessions without a connected helper are now reported as `starting`, `restarting` or `start_failed` with `last_error`, as on Windows, and the clipboard capability says why it isn't covered: `dlp_not_enforcing`, `helper_not_connected` or, only when nobody is logged in, `no_user_session` (#299).

## [v4.0.1] - 2026-10-29

### Fixed

- Clipboard DLP never ran on Windows: the session helper couldn't verify the service's pipe, because it queried the service process, which a user can't do for a LocalSystem service. It now checks the pipe's owner (SYSTEM or Administrators) instead, and the service creates the pipe owned by SYSTEM. A helper that keeps refusing the endpoint now exits after 5 attempts, so the device shows `restarting` instead of `starting` forever. Sessions without a connected helper report why in a new `last_error` field of the DLP status (#292).

## [v4.0.0] - 2026-10-29

### Added

- Groundwork for clipboard Data Loss Prevention (DLP): a new `internal/dlp` subsystem the service starts at boot, and a `dlp_enabled` setting in `config.json` (default `true`). DLP stays off until the server sends a policy that enables it; `dlp_enabled: false` turns it off on that device whatever the server says. Nothing is enforced yet: watching the clipboard comes in later releases (#258).
- DLP detection engine (#259), not yet wired to a channel. It finds secrets with the [betterleaks](https://github.com/betterleaks/betterleaks) ruleset (v1.9.0, 454 high and medium confidence rules), embedded as data and run without network access; personal data (card numbers with a Luhn check, IBANs with a mod-97 check, US SSN, UK NINO and NHS numbers, and opt-in email, phone and country IDs) with [alcatraz](https://github.com/hoophq/alcatraz); and policy-defined regex and keyword rules. Matches are only reported masked (at most the first and last 4 characters) with a SHA-256. `scripts/update-dlp-rules.sh` regenerates the ruleset from a pinned betterleaks tag. It adds about 0.4 MB to the binary.
- DLP policy sync (#260): when `dlp_enabled` is on, the agent polls `agent_get_dlp_policy` every `poll_interval_seconds` (1 minute to 1 hour, default 5 minutes, plus jitter) and keeps the last policy in `dlp_policy.json` next to `config.json` (owner-only; SYSTEM and Administrators on Windows), so it applies at boot before any network call, and an org-wide off stays off after an offline restart. A failed poll keeps the last policy. With each poll the agent reports what it applied (version, supported detectors, rules it couldn't compile, channel capabilities), sending the report only when it changed. A policy with a newer `schema_version` is not applied and is reported instead; one bad rule is skipped and reported while the rest stay active.
- DLP evidence (#261): each flagged copy becomes an event with the policy, action, user, session, source app, masked findings, content length and SHA-256 (an excerpt only when the policy's evidence mode is `full`; with `none`, no masked values). Events are queued in `sentinelgo_dlp.db` next to `config.json` and uploaded every minute through `agent_enqueue_dlp_events` in batches under 1 MB, then deleted once the server has queued them. The same copy under the same policy within 60 seconds raises `repeat_count` instead of adding an event. An offline device keeps at most 10,000 events (20 MB), dropping the oldest and counting the drops. Clipboard content is never logged.
- DLP session helper (#262): the hidden `sentinelgo dlp-session` command runs in a user session, connects to the service over a local named pipe (`\\.\pipe\sentinelgo-dlp`, Windows) or Unix socket (`/var/run/sentinelgo/dlp.sock`), receives the policy, runs the DLP channels and sends events back. The service takes the user and session in each event from the operating system, not from the helper, and the helper only takes policy from the agent's own account (or its own user). When the service is unreachable the helper keeps enforcing the last policy and reconnects. It takes no process lock, reads no credentials and logs to its own file in the user's cache folder. Launching helpers automatically per session comes with the per-OS launchers; until then the service serves the endpoint and a helper can be started by hand.
- DLP on Windows (#263): the service starts one session helper in every active interactive session (console, RDP, fast user switching), as that session's user and without a window, and never in session 0. A helper that exits is restarted with backoff (shown as `restarting` in the status), one whose session ends is stopped, and all of them are stopped when DLP turns off. Helpers run in a job object that ends them with the service, so they never outlive it and a self-update can always replace the binary.
- Clipboard DLP on Windows (#264): the session helper watches the clipboard (event driven, no CPU while idle) and checks copied text against the clipboard policies. A `monitor` policy records an event; a `block` policy replaces the content with the policy's message (for example "Blocked by SentinelOps: credit card") within tens of milliseconds, before it can be pasted, and records the event. Events name the app the content came from, and a policy's exempted apps are skipped. With `ignore_concealed`, copies that password managers mark as secret are ignored. Known gap: Windows clipboard history (Win+V) and cloud clipboard keep what was copied before it was blocked; disable them by Group Policy where DLP matters.
- `sentinelgo dlp status` shows the local DLP state: the local switch, the cached policy (version, when it was cached, the org switch, each policy and any rule that couldn't be compiled), supported detectors, each channel's capability and the evidence queue. `-json` prints it as JSON. `sentinelgo dlp test` runs the cached policy against a file or standard input and prints the policies and detectors that match, with masked values only, and whether the copy would be blocked. Both work offline. `-debug-dump` includes the DLP state (#269).
- Native task `dlp-sync-policy` ("push policy now", also accepted as `dlp_sync_policy`): the agent polls for its DLP policy at once instead of at the next poll, applies it, and reports the applied version and DLP state in the task result. On a device with `dlp_enabled: false` the task fails with that reason (#271).
- DLP on Linux (#267): while DLP enforces, the service installs a systemd user service (`sentinelgo-dlp.service`, started with each graphical session) and an XDG autostart entry for desktops without `graphical-session.target`, and starts the session helper for users already logged in to an X11 or Wayland session. It removes both when DLP turns off, and restarts running helpers once after the agent starts so they use the updated binary. Headless servers start no helper and report the clipboard as `unsupported:no_graphical_session`. Only one helper runs per user session on every OS, and the status reports the clipboard capability the helpers see.
- DLP on macOS (#265): while DLP enforces, the service installs a LaunchAgent (`/Library/LaunchAgents/com.sentinelgo.dlp.plist`) that runs the session helper in every GUI (Aqua) login, never in SSH-only sessions, and loads it for users already logged in (including fast user switching). launchd restarts a crashed helper. The service restarts running helpers once after it starts, so they use the updated binary, and when DLP turns off or the agent is uninstalled it unloads the agent and removes the plist.
- Clipboard DLP on Linux (#268): the session helper checks the clipboard every 0.4 s with the desktop's clipboard tools: `wl-paste`/`wl-copy` on Wayland, `xclip` (or `xsel`) on X11. It records and blocks copies like on Windows, ignores copies a password manager marks as secret (`x-kde-passwordManagerHint`) when the policy says so, and names the source app on X11 when `xdotool` is installed. Where it can't work, the status says why instead of enforcing nothing: `unsupported:wayland_no_data_control` (Wayland compositors without the data-control protocol, such as GNOME), `unsupported:no_wl_clipboard` or `unsupported:no_xclip_or_xsel` (tool not installed), `unsupported:no_graphical_session`.
- Clipboard DLP on macOS (#266): the session helper checks the pasteboard's change counter every 0.25 s and reads the text only when it changes (no cgo; AppKit is called through the Objective-C runtime). It records and blocks copies like on Windows, marks its placeholder so clipboard managers skip it, ignores copies password managers mark as concealed, transient or auto-generated (nspasteboard.org types) when the policy says so, and names the frontmost app (name, bundle ID and path) as the source. Whether recent macOS versions show a pasteboard-access alert for the helper is still to be checked on hardware.
- DLP desktop notification (#270): when a copy is blocked, the user also gets a desktop notification with the policy's `notify_message` (default "SentinelOps blocked sensitive data on your clipboard: {{detector}}"): a toast on Windows, Notification Center on macOS and `notify-send` on Linux. At most one shows every 10 seconds. The text is passed to these tools as data, never as script or shell input, and a notification that can't be shown never affects the block.
- macOS: the software inventory includes each app's bundle ID (such as `com.tinyspeck.slackmacgap`) even when Spotlight indexing is off, or Spotlight couldn't be queried. The agent then reads it from the app's `Info.plist`. The server needs the bundle ID to tell Mac App Store apps apart and to link them to App Catalog apps (#249).
- Network exposure: each risky service the host firewall lets in now says whom it lets in: `remote_scope` is `any`, `local_subnet`, `specific` (with the addresses in `remote_addresses`, up to 10) or `unknown`. `on_public_address` marks a service on a public IP address. On Windows this comes from the allow rules' remote addresses (Windows' File and Printer Sharing rules usually allow only the local subnet), on Linux from the ufw rule's source or the firewalld zone's or rich rule's source, and a firewall that's off counts as `any`. The agent reports the `exposure_scope_v1` capability (#251).

### Changed

- Network exposure has a new **Critical** level, for a risky service let in from any address on a public IP address. A service let in only from the local subnet or listed addresses is now Medium instead of High, and the recommendation says whom it's let in from (#251).
- Windows: firewall allow rules limited to an interface (such as Wi-Fi only), an interface type or a Windows service now count only for connections on that interface, or for the process hosting that service. Before, they counted everywhere, so some services were reported as reachable when they weren't (#251).

### Fixed

- DLP (review follow-ups to #258, #259, #260): a long line of placeholder tokens could hide a real secret after it, and a custom pattern that can match empty text could hide a later match (the per-rule cap now counts only real findings). Base64 JWTs are reported as the whole token instead of one claim. `secrets.all` with a `min_count` counts a token matched by two rules once. A policy whose content changed under the same version is recompiled. `max_scan_bytes` is capped at 4 MB. The DLP status says `stopped` after shutdown even when DLP was off locally.
- DLP (follow-up to #259): the embedded secrets ruleset no longer contains key-shaped strings. betterleaks deny-lists some publicly known Google API keys so they aren't reported; the generator now stores such literals hex-encoded, with the same effect.
- Network exposure (follow-up to #251, from the review of #255): a service is rated Critical only when the firewall lets it in on a network that has a public address. On Windows, a rule for the private network only no longer makes it Critical because another network has a public address (Linux accepts traffic for any of its addresses on any interface, so a ufw or firewalld rule limited to one interface still counts), and an IPv6-only socket no longer counts the host's public IPv4 address. Special-use ranges (benchmarking `198.18.0.0/15`, documentation, reserved) don't count as public. A source of `0.0.0.0/0` or `::/0` is `any`, not `specific`. Windows' `DefaultGateway` keyword is `specific`, not `any`. A firewalld zone bound to an interface as well as sources lets in any address. An allow whose ufw profile or firewalld service can't be read now adds whom it may let in to the scope (`unknown` when that's anyone) instead of being ignored. A service whose firewall state couldn't be verified is no longer described as "allowed in from any address", and a service on two networks is listed once with both profiles.
- Linux SSH (follow-up to #250): a quoted `Include` in `sshd_config` is followed, and an `Include` outside `/etc/ssh` is skipped. When there's no sshd binary or config at the standard paths but the `ssh` or `sshd` unit is running, the settings are `Unknown` instead of `Not installed`. The settings are sshd's global ones; a `Match` block's overrides aren't reported.
- Linux: SSH root login, password authentication and key authentication no longer show as Unknown on stock Ubuntu and Debian hosts. The agent reads the settings sshd actually uses (`sshd -T`), and when that fails it parses `sshd_config` the way sshd does: it follows `Include` files such as `sshd_config.d/50-cloud-init.conf`, keeps the first value of a setting, ignores `Match` blocks and uses OpenSSH's defaults for settings that aren't set. `PermitRootLogin forced-commands-only` and `without-password` now count as Disabled. A device without an SSH server reports "Not installed". Hosts that never set `PasswordAuthentication` now show it as Enabled, which is OpenSSH's default, so the console starts recommending to disable it (#250).

## [v3.7.2] - 2026-10-27

### Added

- The agent sends inventory right after a system command's script has run (USB storage, autorun, BitLocker, hostname, package install, OS update and the other console toggles and policies), instead of waiting for the next scheduled inventory report. Several system commands in one batch share one sync, which runs after every task's status is reported. It needs the backend to send `command_kind` with each task (sentinel-ops#403); until then nothing changes. A `native` command this agent version doesn't implement now fails with "not supported by this agent version" instead of "no script found for platform" (#231).

### Fixed

- The agent's single-instance lock is now held by the operating system (a share-deny handle on Windows, `flock` on Linux and macOS) instead of trusting the PID written in the lock file. The OS releases it however the agent exits (self-update, `-stop`, kill, crash, power loss), so a leftover lock file can no longer stop the service from starting. On Windows the service could stay down for good with "Error 1: Incorrect function" once another process reused the PID in a stale lock file. The lock now lives at `C:\SentinelGo\.sentinelgo\sentinelgo.lock` on Windows (it was under the account's profile, e.g. `systemprofile`), and the service and `-run` use the same lock, so they can't run at the same time. A failed Windows service start is written to the Event Log and reported as a service-specific exit code in `sc query`: 2 already running, 3 lock file error, 4 invalid config, 5 other startup failure (#242). `sentinelgo -run` exits with the same code (2 or 3) when it can't take the lock, instead of exiting 0 without starting.
- A system command whose script never started (its interpreter, such as `pwsh` or `zsh`, isn't installed, or the process failed to launch) no longer triggers the inventory sync after the batch.

## [v3.7.1] - 2026-10-23

### Added

- `.ps1` task scripts run on macOS and Linux under PowerShell 7, as `pwsh -NoProfile -NonInteractive -File <script> -PayloadPath <payload>`, the same arguments as on Windows. A command with a single cross-platform `.ps1` in its `all` slot now runs on every OS. The agent adds `script_pwsh_v1` to its inventory capabilities only when `pwsh` is installed, and checks again on every inventory report. Without `pwsh`, a `.ps1` task fails with "PowerShell (pwsh) is not installed on this device" instead of an exec format error (#222).
- `network_exposure_access.risky_services` in the inventory payload: each commonly attacked service listening on a non-loopback address, with `name`, `port`, `protocol`, `address`, `scope` (`all` for a wildcard bind, `interface`, or `unknown`), `process_name` and `firewall`. The catalogue is SMB (139, 445), NetBIOS (137–138/udp), RDP, WinRM, SSH, Telnet, FTP, VNC (5900–5906), MSSQL, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, the Docker API, Kubelet and SNMP. `firewall` says whether the host firewall lets inbound connections reach the service: `allowed`, `blocked`, `disabled` or `unknown`. Windows evaluates the inbound rules in force (local and Group Policy) against the profile of each connected network, and lists the profiles that let the service in as `reachable_profiles`. A service bound to one interface's address is checked against that network's profile only, and an incomplete rule set gives `unknown`. Linux evaluates ufw rules (IPv4 and IPv6 separately, with interface- and destination-scoped rules applied only where they reach) or firewalld zones (a service bound to one interface gets its zone and the source zones). macOS reports `disabled` when the Application Firewall is off and `blocked` when it blocks all incoming connections. `firewall_security.network_profiles` lists the firewall profile (Domain, Private or Public) of each connected network on Windows (#221).
- Who administers and uses the device, in the inventory payload (#223):
  - `local_admin_members`: every member of the local administrators group, with `name`, `sid` (Windows), `source` (`local`, `domain` or `entra`) and `principal_class` (`user` or `group`). On Windows this is the Administrators group, found by its SID, so domain users and groups and Entra ID principals are included. When `Get-LocalGroupMember` fails on an unresolvable Entra SID, the agent reads the group through ADSI. On macOS it is the `admin` group; on Linux, the `sudo`, `wheel` and `admin` groups, including directory users and groups seen through `getent`, and accounts (directory ones too) whose primary group is one of them.
  - `signed_in_users`: the interactive sessions, with `username`, `session` (`console`, `rdp`, `ssh` or `terminal`) and `since`. Windows reads them from the Remote Desktop Services API and also reports `domain` and `state` (`active` or `disconnected`). macOS and Linux read `who`.
  - `last_signed_in_user`: from LogonUI on Windows, the login window on macOS and `last` on Linux.
  - `identity_join`: `type` (`workgroup`, `domain`, `entra` or `hybrid`) with `domain`, `tenant_id` and `tenant_name` where they apply, from `dsregcmd /status` on Windows, `dsconfigad` on macOS and `realm list` on Linux.
  
  A list the agent couldn't read is sent as `null`, and an empty one as `[]`. The agent advertises the new `users_inventory_v2` capability.
- macOS reports `last_logon` for local accounts, from the login records (`last`). It is left out for an account with no record, since the records are rotated (#223).

### Fixed

- Linux UFW firewall evaluation accounts for multiple active network interfaces. A deny rule on one interface (e.g. `eth0`) only blocks all traffic when it's the only active interface. When multiple interfaces are up (ethernet + WiFi, VPN, etc.), a deny on one doesn't decide the verdict for traffic arriving on another. The exposure verdict now reflects which connections can actually reach the socket (#221).
- Linux UFW firewall evaluation detects IPv6-only sockets. A socket on `::` is treated as IPv6-only when the same port also has an IPv4 wildcard socket (Linux refuses that pair unless the IPv6 one is `IPV6_V6ONLY`). Otherwise it's still assumed dual-stack, since `net.ipv6.bindv6only` is only a default that a socket can override, so exposure is never understated (#221).
- Linux firewalld evaluation applies the default zone to a service listening on every address whenever a network interface isn't bound to a zone, since firewalld sends that interface's traffic to the default zone. A service the default zone opens was reported `blocked` when another zone was active (#221).
- Windows firewall evaluation honours "block all incoming connections" (`AllowInboundRules` off): allow rules no longer make a service `allowed` on that profile (#221).
- Windows firewall evaluation reads each rule's local and remote addresses. An allow rule for one local address no longer counts for a service bound to another. A block rule decides only when it covers every connection to the service: from any remote address, to the service's address, and for its program. A block from one subnet, or a block for one program when the listening process is unknown, no longer reports a reachable service as `blocked` (#221).
- macOS reports the Application Firewall as enabled when it blocks all incoming connections (state 2). The firewall was reported off, and every risky service `disabled`, instead of `blocked` (#221).
- Windows reports its built-in Administrator, Guest, DefaultAccount and WDAGUtilityAccount in `local_users`, with `is_builtin: true`, instead of leaving them out. An enabled built-in Administrator is what compliance checks look for. They are found by RID (500, 501, 503, 504), so a renamed Administrator is still flagged. Setup's `defaultuser*` sandbox accounts are still left out (#223).
- Network exposure is rated by the risky services a device exposes, not by how many sockets are bound outside loopback. A stock Windows 11 device used to be rated High for its mDNS, WS-Discovery and RPC listeners. `network_exposure_level` is now High when a risky service can be reached (or the agent can't tell), Medium when every risky service is blocked by the host firewall, and Low when there are none. Medium no longer costs the posture-score point. The recommendation names the services, e.g. "Close or firewall SMB (445/tcp), RDP (3389/tcp)" (#221).
- Listeners on loopback are never counted as exposed. `127.0.0.0/8` (e.g. systemd-resolved on `127.0.0.53`), `::1` and IPv4-mapped loopback addresses used to count toward `publicly_bound_ports`. SSH or WinRM bound to loopback was also reported in `open_administrative_ports` and `remote_access_services`. `open_administrative_ports` now lists the ports of `risky_services` (#221).
- The exposure analysis covers every listening socket. Only the `listening_ports` list sent in the payload is capped at 200, so a risky service listed after the cap is no longer missed on a busy host (#221).
- `.bash` and `.zsh` task scripts on macOS and Linux run with `bash` and `zsh`, like `.sh`, instead of being executed directly. They no longer fail when the console's prepended lines push the shebang off line 1. `zsh` must be at a fixed system path; without it a `.zsh` task fails with "zsh is not installed on this device" (#222).

### Security

- The Linux firewall probes run `firewall-cmd`, `iptables` and `nft` from fixed system paths instead of searching `PATH`, where a writable directory could substitute them while the agent runs as root.

- Built with Go 1.26.10, which makes `crypto/x509` distrust compromised intermediate certificates (GO-2026-6809). This affects every TLS connection the agent makes to the backend.

## [v3.7.0] - 2026-10-20

### Added

- Publisher, install date, size and architecture for each item in the software upload, as `publisher`, `install_date` (RFC 3339), `size_bytes` and `architecture`, plus `bundle_id` for macOS apps. Windows reads them from the uninstall keys (32-bit programs are those under `Wow6432Node`) and from `Get-AppxPackage`, where the install date is the creation time of the package's folder. macOS reads the signing certificate and `arch_kind` from `system_profiler`, the date added, size and bundle ID from Spotlight, and the tap and install time from `brew info`. Linux reads dpkg's maintainer, size and architecture (the install date is the time of the package's file list), rpm's vendor, size, install time and architecture, the snap publisher with the date and size of the installed revision, and the flatpak origin and architecture. `architecture` is one of `x64`, `x86`, `arm64`, `arm`, `universal` or `noarch`. A value the platform doesn't have is left out (#209).

### Fixed

- Debian and Ubuntu devices report their installed packages. The `dpkg-query` format had no line separator, so the whole package list arrived as a single malformed entry. Packages that were removed but still have configuration files are not reported (#209).
- A deb or rpm package installed for two architectures (e.g. `libc6` for amd64 and i386, `glibc` for x86_64 and i686) is reported once per architecture, as `name:arch`, instead of one overwriting the other (#209).
- Flatpak apps whose name contains a space are reported with their full name and version. The columns were split on whitespace instead of tabs (#209).

## [v3.6.1] - 2026-10-20

### Added

- Measured power draw in `power_telemetry`, where the device reports one. A laptop running on battery reports its battery's discharge rate: `/sys/class/power_supply` on Linux, WMI `BatteryStatus` on Windows (read in-process, no PowerShell) and `ioreg` on macOS. Apple Silicon and T2 Macs also report the adapter's power to the system while on AC and not charging. The window adds `on_ac_samples`, `measured_samples`, `measured_watts_avg` and `measured_source` (`battery` or `apple_system_power`). Readings taken while charging aren't counted, because they include the charge current. Values outside 0–500 W are dropped. Desktops, VMs and non-Apple laptops on AC send no `measured_*` fields (#199).
- AutoRun/AutoPlay and application-control state in the inventory payload, for the server's CIS, ISO 27001 and NIST CSF checks. `security_info.autorun` reports `autorun_disabled` and `autoplay_disabled` on Windows, from the AutoRun policies and each signed-in user's AutoPlay setting. `security_info.application_control` reports the strongest product and its mode (`enforced`, `audit` or `off`): WDAC and AppLocker on Windows, Gatekeeper on macOS and fapolicyd on Linux. WDAC is read from its user-mode status, because the kernel-mode status also counts Windows 11's built-in driver blocklist. AppLocker rules count only while the Application Identity service is running. A value the agent can't read is left out (#178).
- Average CPU usage in the inventory payload, for the server's device energy estimate. Each upload carries a `power_telemetry` object covering the whole time since the previous successful upload: `window_start`, `window_end`, `samples` (agent-info ticks in the window, roughly the time the machine was awake) with `sample_interval_seconds`, and `cpu_usage_avg_percent`. The average comes from CPU time counters read on every agent-info tick, including ticks that don't upload. A failed upload keeps adding to the window, so no time is lost. The object isn't part of the change check, so inventory isn't uploaded more often. It is left out until the first interval after the agent starts has completed (#198).

### Security

- Errors from the backend are written to the agent's log with line breaks removed, so a crafted server response can't add forged lines to the log (CWE-117). This covers sign-in, token refresh, task polling and execution, and audit log upload errors.

## [v3.6.0] - 2026-10-15

### Added

- Every partition of every disk in the inventory payload, as `disks[].partitions[]`, with the disk's `disk_number`. Each partition reports its number, type (EFI, MSR, Recovery, Basic or the platform's type name), drive letter, mount point, label, volume GUID, file system, size, free space, boot/system flags and its own encryption state (`full`, `partial`, `none`, `encrypting`, `decrypting` or `unknown`) with provider, method, protection status and progress. Windows lists all partitions, lettered or not, from `Get-Partition` and matches them to `Get-BitLockerVolume`; Linux reads the `lsblk` tree, so a LUKS partition and the file system inside it are reported together; macOS reads `diskutil` and reports each APFS volume with its FileVault state. A BitLocker volume reports its RecoveryPassword protector id as `key_protector_id` so the server can link it to an escrowed key; the recovery password itself is never collected. Partition data previously came from the server's `disk-partition-inventory` script (#179).

### Fixed

- A BitLocker volume that is fully encrypted but has protection suspended (common during Windows updates and firmware changes) no longer reports the disk's `encryption_status` as `disabled`. The disk-level status now comes from whether the OS or data volume is actually encrypted (`VolumeStatus`), not from `ProtectionStatus`, and a Windows install without the BitLocker module (Windows Home) reports `unknown` instead of `disabled`. On Linux, a disk is no longer reported as encrypted just because some other disk has an open dm-crypt mapping (#179).

### Security

- Release binaries are built with Go 1.26.9 instead of 1.26.0. Go 1.26.0's standard library has 28 known vulnerabilities that the agent's code can reach, among them IPv6 host parsing in `net/url` and certificate name-constraint checks in `crypto/x509`, which the updater and Supabase client use. `go.mod` now names the toolchain (`toolchain go1.26.9`), so local builds use it too. CI missed these because govulncheck ran with the latest Go (1.27) instead of the version releases are built with; it now runs with the release Go version (#183).
- Releases can no longer ship a vulnerable Go toolchain or dependency unnoticed. The release workflow scans every built binary with `govulncheck -mode=binary` and stops before signing if any reachable vulnerability is found. Each binary records the Go that built it, so this works whatever the CI setup. A weekly scan also checks `main` and the latest published release, and opens an issue when it finds something. The Go version is now set only in `go.mod`, so builds and scans can't use different versions.

## [v3.5.1] - 2026-10-14

### Added

- Compliance telemetry in the inventory payload, for the server's compliance checks: `security_info` now reports `screen_lock`, `password_policy`, `auto_login_enabled`, `guest_account_enabled`, `remote_access`, `patching`, `audit_logging`, `time_sync` and `backup`, and each `local_users` entry adds `is_enabled`, `last_logon` and `password_last_set`. All of these keys are optional: a value the agent can't read is left out, so the server shows that check as unknown instead of failing it. Settings that only suggest an answer are left out too: a Windows backup agent whose service starts manually, Windows Update or time sync whose settings couldn't be read, and a screen-lock timeout when one of the idle or lock-delay settings couldn't be read. Windows reads them from the registry, `secedit`, `auditpol`, Windows Update and `Get-LocalUser`; macOS from `pwpolicy`, `sysadminctl`, the login window, Software Update and Time Machine settings; Linux from PAM, `/etc/shadow`, `lastlog`, display-manager config, systemd units, the package manager, auditd and the time daemon (#172).

### Changed

- Windows `critical_kbs_missing` matches Security and Critical updates by category ID instead of by category name, so it also works on Windows installs in other languages. The Windows Update search now runs once per collection and also feeds `patching.missing_updates` (#172).

### Fixed

- macOS compliance collection range-checks the integers it reads from property lists (password-policy parameters, screen-saver idle time, password delay). An out-of-range value is now treated as unreadable instead of overflowing when converted (#176).

### Security

- The OS info collectors run system tools from their fixed install paths (`internal/binpath`) instead of looking them up in `PATH`, so a writable `PATH` directory can't substitute a tool while the agent runs as root or SYSTEM (CWE-426/427). This now covers the compliance probes and every other tool `binpath` knows, including programs started through `runuser`, `env`, `sudo` and `launchctl asuser`. A known tool that isn't installed at its fixed path is skipped, and is no longer looked up in `PATH` (#172).

## [v3.5.0] - 2026-10-13

### Added

- `docs/assurance-case.md`: the security assurance case (requirements, threat model, trust boundaries, secure-design principles and the weaknesses countered).
- `ROADMAP.md`: what's planned for the next releases and beyond.
- Coding standards and code review sections in `CONTRIBUTING.md`.
- OpenSSF Best Practices badge in the README.
- `internal/artifact`: downloads the files a task needs (such as installer packages) from Supabase Storage with the agent's own token, streaming them to disk while checking the exact size and SHA-256. A file that doesn't match is deleted. Downloads retry on network errors and 5xx, recover once from an expired token, abort when no data arrives for 2 minutes, and check free disk space first (#136).
- Script tasks can carry `artifacts`: files such as installer packages that the agent downloads and verifies before the script runs. The script finds them through `SENTINEL_ARTIFACT_<ID>` environment variables and the `artifacts` key in `payload.json`. If any file fails verification, the script doesn't run and the task note names the artifact. Artifacts are kept in the local task database, so a restart between polling and execution doesn't lose them. Every script task now also gets `SENTINEL_TASK_ID`, `SENTINEL_TASK_DIR` and `SENTINEL_ARTIFACTS_DIR` (#137).
- The inventory payload lists the task features the agent supports (`capabilities`: `script_inline_body_v1`, `task_artifacts_v1`), so the backend won't send installer tasks to agents that can't run them. `sentinelgo -version` prints the list (#138).
- Script tasks report a structured result next to the note: the script's exit code, plus anything the script writes as a JSON object (up to 16 KiB) to the file named by `SENTINEL_RESULT_FILE`, such as `reboot_required`. The agent always sets `exit_code` itself. Older backends without the new `p_result` parameter keep working: the agent retries once without it and stops sending it. The result is kept locally, so a report retried after a network failure still carries it (#140).

### Changed

- README redesigned for first-time visitors: a header banner, what SentinelGo does and collects at a glance, a three-step quick start, and configuration, CLI and build details folded into expandable sections.
- Release binaries are reproducible: builds use `-trimpath`, and the installer and release scripts are committed as executable so CI builds from an unmodified tree. Anyone can rebuild a release and compare it with `SHA256SUMS`; see "Reproducing a release" in `RELEASE.md`.
- CI runs the test suite with the Go race detector.
- `SECURITY.md` corrected to match the code: release signatures are verified (not "planned"), updates come from Supabase rather than the GitHub API, credentials are protected by file permissions rather than an OS credential store, and the CI controls list is complete. Adds a "What to expect" section on what SentinelGo does and doesn't protect against.
- `docs/08-project-overview.md` updated to the current package layout.
- A failed task whose payload sets `"retry_on_failure": false` is no longer retried automatically. Installers use this so a failed install isn't downloaded and run again after the user has already seen the failure. Tasks without the key retry as before (#139).
- Task notes are capped at 64 KiB: the first 8 KiB and the last 56 KiB of the output, with a marker showing how much was cut. A `SENTINEL_REBOOT_REQUIRED` line is always kept. Script output is collected in bounded memory instead of being held in full (#139).
- On Linux, environment variables the agent passes to a task script now reach it when the script runs through `sudo` (#139).

### Removed

- `docs/09-system-architecture.md`, `EXECUTION_FLOW.md` and `process_flow.md`, which `docs/08-project-overview.md` had superseded and which described components that no longer exist.

### Fixed

- Tasks whose script is sent inline (`scripts.<os>.body`, no storage path) now run. Previously every policy-triggered app install failed with `no script found for platform`. Inline filenames are checked so a server value can't write outside the task's temp directory, and empty or over-10 MiB bodies fail the task (#135).
- A task that failed while the agent was offline is no longer retried before its failure reaches the server. Previously the retry reset it after 5 minutes, before the pending report was sent, so the server never saw that attempt's status and output.

### Security

- Windows: local account names and network adapter names are now quoted safely before being passed to PowerShell. Previously, a local account whose name contained `$(...)`, or an adapter name containing a quote, would have run as a command with the agent's SYSTEM privileges. Creating such an account or renaming an adapter requires administrator rights.

## [v3.4.0] - 2026-10-09

### Added

- Project website at <https://brainstation-23.github.io/SentinelGo/>, published from `site/` by GitHub Pages.
- This changelog. Release notes are now taken from it instead of being generated from commit messages.
- `scripts/changelog` tool (`-check`, `-extract`, `-release`, `-latest`) and CI check: pull requests must add a changelog entry unless labelled `skip-changelog`.
- FOSSA license scan status badge in the README.
- `GOVERNANCE.md`: roles, how decisions are made, how to become a maintainer, and how the project continues if the maintainer is unavailable.

### Changed

- One-click releases: **Trigger Release** moves the `[Unreleased]` entries under the new version in a "Release vX.Y.Z" pull request that merges itself once checks pass, and the new **Tag Release** workflow tags `main` when it merges. A dry-run option shows the release notes first.
- `RELEASE.md` rewritten to describe the current release process.
- `CHANGELOG.md` and `RELEASE.md` are linked from the README.

### Removed

- `RELEASE_NOTES.md` and `RELEASE_PROCESS.md`, which described an outdated process and release.

### Fixed

- `-agent-info-update` reports a payload the backend rejected as a failure instead of success.
- Scheduler: the last-run time is read and written atomically, and tasks can no longer be added after the scheduler has started.
- Shutdown stops the task manager before closing its store, so in-flight tasks no longer write to a closed database.
- Linux displays: EDID data split across several `xrandr` lines is read correctly, and `edid-decode` product strings are preferred.
- macOS security posture: bootstrap token, secure token and Touch ID status are parsed from the real command output, and duplicate EDR products are removed.
- Linux security posture: pending updates are read from `apt-check`'s stderr, and the newest ClamAV scan is reported.
- Linux GPUs: total VRAM is read from `rocm-smi` by column name rather than position.
- Updater: a downloaded binary that fails its checksum is deleted instead of being left on disk.
- Updater: after a failed copy the backup file is closed before it is removed, so the removal succeeds on Windows.
- Windows lock file: the running-process check opens the process with `SYNCHRONIZE` access, so a live agent (exit code 259) is detected.

### Security

- The Trigger Release workflow passes its inputs through environment variables instead of interpolating them into the shell script, and rejects versions that aren't `vX.Y.Z`.

## [v3.3.0] - 2026-10-08

### Added

- `internal/supabase`, a single in-house client for all Supabase RPC, Storage, auth and Edge Function calls, with typed errors.
- Go fuzz targets for the audit-log parsers, checkpoint handling, updater version comparison and signature checks, Linux EDID decoding, extension metadata and per-OS command-output parsers, plus `make fuzz` and a nightly fuzzing workflow.
- License compliance tooling: an allow-list check in CI, a `THIRD_PARTY_NOTICES.txt` file and a CycloneDX SBOM for each release binary.
- Build provenance attestations for the release binaries and installers.
- OpenSSF Scorecard workflow and badge.
- `SECURITY.md`, a contributing guide and issue templates.

### Changed

- All Supabase access goes through `internal/supabase`; the `supabase-go` and `postgrest-go` SDKs are no longer used.
- Authentication errors are classified by HTTP status rather than by matching error strings.
- The updater checks for releases through a Supabase RPC that reports its status and retries once after re-authenticating.
- Update-check jitter uses cryptographic randomness.
- Link speed (`linkSpeedMbps`) is only collected on macOS and Windows, where it is available.
- Reduced complexity and duplication across the per-OS collectors.

### Removed

- The legacy `AutoUpdateChecker`; the updater now follows the Supabase release flow only.

### Fixed

- Token refresh sends the anon API key, so sessions renew instead of expiring.
- Payloads that receive HTTP 408 or 429 are retried instead of dropped.
- Three crashes in command-output parsers found by fuzzing; malformed values are now rejected.
- Placeholder locale names in browser extension metadata are resolved.

### Security

- Installers verify the downloaded binary against `SHA256SUMS` and refuse to install if the checksum file is missing.
- The installers are signed, checksummed and attested like the binaries.
- External commands are run by absolute path, closing a `PATH`-hijacking risk in 21 files.
- Scripts downloaded from Storage are rejected if they exceed the size limit.
- GitHub Actions are pinned to full commit SHAs and workflow tokens use least-privilege permissions.
- Binaries and runtime databases that had been committed by mistake were removed from the repository.

## [v3.2.8] - 2026-09-23

### Changed

- Updated Go and CI dependencies.

### Security

- The Supabase URL must use HTTPS.
- The install directory and agent binary get restrictive permissions.

## [v3.2.7] - 2026-07-20

### Changed

- Browser extensions report their extension ID as `Name` and the human-readable label as `DisplayName`.

## [v3.2.6] - 2026-06-17

### Added

- Software catalog, and software collection for every user account on the machine.

## [v3.2.5] - 2026-06-17

### Added

- `-debug-dump` flag that prints every collector's output as JSON.

### Security

- Sensitive values are no longer written to logs in clear text.

## [v3.2.4] - 2026-06-16

### Added

- Host security posture assessment for Windows, macOS and Linux, including patch and update compliance.

### Changed

- Payloads are sent through an enqueue RPC with retries and de-duplication.

### Fixed

- Parsing of security posture command output.

## [v3.2.3] - 2026-06-16

### Added

- Collection of operating-system services, with CLI support, a sync RPC and task handlers.

## [v3.2.2] - 2026-06-16

### Fixed

- An app is only reported as uninstalled after it is missing from 2 consecutive scans.
- Software collection commands run with timeouts.

## [v3.2.1] - 2026-06-16

### Added

- Emergency log: rare fatal failures (such as rejected credentials or tokens that can't be saved) are written to daily files kept for 3 days.
- A scheduled task that fails 3 times in a row raises one alert, and its recovery is logged.

### Changed

- Authentication recovery was reworked and is shared by logging and the scheduler.
- Software reconciliation only removes entries from sources that were actually scanned.

## [v3.2.0] - 2026-06-15

### Changed

- The updater checks for releases through a Supabase RPC and downloads binaries from Supabase Storage.

## [v3.1.3] - 2026-06-15

### Added

- Task handlers to enable and disable the firewall.
- Better peripheral detection and last-opened times for installed software.

## [v3.1.2] - 2026-06-14

### Added

- Double-click installers (`install.command`, `install.bat`, `sentinelgo-install.desktop`) included in releases.

### Fixed

- Errors from closing files and writing output are no longer ignored.

## [v3.1.1] - 2026-06-14

### Changed

- Printer detection parsing moved into separate, tested helpers.

## [v3.1.0] - 2026-06-13

### Added

- Per-task timeouts (`timeout_minutes` in the task payload) enforced by a watchdog that cancels overdue tasks.
- `reboot-device` task handler. Planned restarts are recorded so the triggering task is reported as successful rather than interrupted.

## [v3.0.3] - 2026-06-12

### Fixed

- macOS hardware and software inventory fixes.

## [v3.0.2] - 2026-06-12

### Added

- Native task handler framework with the first set of handlers.

## [v3.0.1] - 2026-06-11

### Added

- USB mass-storage device detection.

### Changed

- macOS service installation reworked.

## [v3.0.0] - 2026-06-11

### Fixed

- Audit-log checkpoint parsing, config handling and startup ordering.
- Hardware collection has a timeout, so a hung query can't stall agent-info updates.
- Tasks are marked as executing before they run, and tasks interrupted by a restart are marked failed instead of being run again.

### Security

- Release binaries are signed with Ed25519. The updater verifies the SHA-256 checksum and the signature before installing an update, and refuses updates with a missing or invalid signature.

## [v2.2.1] - 2026-06-11

### Changed

- Audit-log collectors reworked and improved.

## [v2.2.0] - 2026-06-10

### Added

- Network adapters report their device name.

### Changed

- Upgraded to gopsutil v4.
- Service lifecycle code moved into the service package.

### Fixed

- Windows software collection has timeouts, so a hung query can't stall the agent.

## [v2.1.18] - 2026-06-09

### Added

- More network details, extended Windows OS information and the timezone offset.
- More complete macOS system information.

## [v2.1.17] - 2026-06-09

### Added

- First release recorded in this repository: the cross-platform agent that reports system metrics to Supabase as a heartbeat and runs as a Windows Service, systemd unit or launchd daemon.

[Unreleased]: https://github.com/BrainStation-23/SentinelGo/compare/v4.0.8...HEAD
[v4.0.8]: https://github.com/BrainStation-23/SentinelGo/compare/v4.0.7...v4.0.8
[v4.0.7]: https://github.com/BrainStation-23/SentinelGo/compare/v4.0.6...v4.0.7
[v4.0.6]: https://github.com/BrainStation-23/SentinelGo/compare/v4.0.5...v4.0.6
[v4.0.5]: https://github.com/BrainStation-23/SentinelGo/compare/v4.0.4...v4.0.5
[v4.0.4]: https://github.com/BrainStation-23/SentinelGo/compare/v4.0.3...v4.0.4
[v4.0.3]: https://github.com/BrainStation-23/SentinelGo/compare/v4.0.2...v4.0.3
[v4.0.2]: https://github.com/BrainStation-23/SentinelGo/compare/v4.0.1...v4.0.2
[v4.0.1]: https://github.com/BrainStation-23/SentinelGo/compare/v4.0.0...v4.0.1
[v4.0.0]: https://github.com/BrainStation-23/SentinelGo/compare/v3.7.2...v4.0.0
[v3.7.2]: https://github.com/BrainStation-23/SentinelGo/compare/v3.7.1...v3.7.2
[v3.7.1]: https://github.com/BrainStation-23/SentinelGo/compare/v3.7.0...v3.7.1
[v3.7.0]: https://github.com/BrainStation-23/SentinelGo/compare/v3.6.1...v3.7.0
[v3.6.1]: https://github.com/BrainStation-23/SentinelGo/compare/v3.6.0...v3.6.1
[v3.6.0]: https://github.com/BrainStation-23/SentinelGo/compare/v3.5.1...v3.6.0
[v3.5.1]: https://github.com/BrainStation-23/SentinelGo/compare/v3.5.0...v3.5.1
[v3.5.0]: https://github.com/BrainStation-23/SentinelGo/compare/v3.4.0...v3.5.0
[v3.4.0]: https://github.com/BrainStation-23/SentinelGo/compare/v3.3.0...v3.4.0
[v3.3.0]: https://github.com/BrainStation-23/SentinelGo/compare/v3.2.8...v3.3.0
[v3.2.8]: https://github.com/BrainStation-23/SentinelGo/compare/v3.2.7...v3.2.8
[v3.2.7]: https://github.com/BrainStation-23/SentinelGo/compare/v3.2.6...v3.2.7
[v3.2.6]: https://github.com/BrainStation-23/SentinelGo/compare/v3.2.5...v3.2.6
[v3.2.5]: https://github.com/BrainStation-23/SentinelGo/compare/v3.2.4...v3.2.5
[v3.2.4]: https://github.com/BrainStation-23/SentinelGo/compare/v3.2.3...v3.2.4
[v3.2.3]: https://github.com/BrainStation-23/SentinelGo/compare/v3.2.2...v3.2.3
[v3.2.2]: https://github.com/BrainStation-23/SentinelGo/compare/v3.2.1...v3.2.2
[v3.2.1]: https://github.com/BrainStation-23/SentinelGo/compare/v3.2.0...v3.2.1
[v3.2.0]: https://github.com/BrainStation-23/SentinelGo/compare/v3.1.3...v3.2.0
[v3.1.3]: https://github.com/BrainStation-23/SentinelGo/compare/v3.1.2...v3.1.3
[v3.1.2]: https://github.com/BrainStation-23/SentinelGo/compare/v3.1.1...v3.1.2
[v3.1.1]: https://github.com/BrainStation-23/SentinelGo/compare/v3.1.0...v3.1.1
[v3.1.0]: https://github.com/BrainStation-23/SentinelGo/compare/v3.0.3...v3.1.0
[v3.0.3]: https://github.com/BrainStation-23/SentinelGo/compare/v3.0.2...v3.0.3
[v3.0.2]: https://github.com/BrainStation-23/SentinelGo/compare/v3.0.1...v3.0.2
[v3.0.1]: https://github.com/BrainStation-23/SentinelGo/compare/v3.0.0...v3.0.1
[v3.0.0]: https://github.com/BrainStation-23/SentinelGo/compare/v2.2.1...v3.0.0
[v2.2.1]: https://github.com/BrainStation-23/SentinelGo/compare/v2.2.0...v2.2.1
[v2.2.0]: https://github.com/BrainStation-23/SentinelGo/compare/v2.1.18...v2.2.0
[v2.1.18]: https://github.com/BrainStation-23/SentinelGo/compare/v2.1.17...v2.1.18
[v2.1.17]: https://github.com/BrainStation-23/SentinelGo/releases/tag/v2.1.17
