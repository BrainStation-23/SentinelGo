# File DLP: what it covers and what it doesn't

**File DLP stops accidental leaks: the wrong file copied to a USB stick, a share or an upload. It doesn't stop a determined insider.**

Someone with admin rights, encryption tools, a phone camera or a second operating system can get data out. Read every row below with that in mind: "covered" means the usual, accidental way is caught, not that every way is.

## Where it runs today

| Platform | What runs | Mode |
|---|---|---|
| Linux | USB sticks, SD cards and other removable drives; SMB, NFS and sshfs shares (files written there are scanned) | Audit only by default. With a `block` policy and audit-only off, copies by copy programs (`cp`, `rsync`, file managers) are refused before anything is written; other writes are judged after the write (`on_close_violation`) |
| Windows, macOS, Linux (uploads) | Uploads to the sites the policy lists, through a local HTTPS inspection proxy the system proxy setting points at (opt-in: `uploads.inspection`; on Linux each user's GNOME or KDE proxy setting). Apps that pin certificates or encrypt client-side aren't inspected. Apps that ignore the system proxy: with `direct_block: quic` (the default) they keep reaching the listed sites over TCP; with `strict`, Windows refuses their direct HTTPS to those sites' addresses, and Linux redirects it into the proxy, which inspects the listed sites and passes every other site on those addresses through. On macOS the inspection CA must be trusted through MDM | Audit only by default; can refuse an upload when audit-only is off. Blocking or redirecting direct connections also only happens when audit-only is off |
| Any (manual test tool) | `sentinelgo dlp proxy`: the same proxy run by hand, for testing | Can block, when the policy allows it |
| Windows | USB sticks, SD cards and other removable drives; the user's mapped network drives; OneDrive, Dropbox, Box, iCloud Drive and Google Drive folders (files written there are scanned once the writer closes them) | Audit only by default. Windows can't refuse a copy before it lands (there is no driver), so a `block` policy acts after the write: `on_close_violation` records, quarantines or deletes the file. Untrusted drives can be made read-only (`untrusted_devices`). With `process_taint` on, the event names the program that wrote the file |
| Windows (network controls) | Apps listed in `network_control.blocked_apps` can't connect anywhere except loopback and the allowed destinations. With `taint_block`, an egress app that opens a user file a `file.upload` block policy matches loses its new connections for a few minutes (every window of that app; connections it already has stay open; a very fast upload can finish before the scan does). Opt-in; WFP filters that disappear if the agent stops | Audit only by default: the status lists what would be blocked, and taint blocks are recorded as `would_have: network_blocked` |
| macOS | USB sticks and other removable drives; SMB, NFS, AFP and WebDAV shares (files written there are scanned) | Audit only by default. Like Windows, a `block` policy acts after the write (`on_close_violation`), and untrusted drives can be mounted read-only. Refusing a copy before it lands comes with Endpoint Security, which needs Apple's entitlement |

## Coverage

| What leaves the device | Status | Notes |
|---|---|---|
| A renamed file (`.xlsx` saved as `.jpg`) | Covered | The type comes from the file's content, not its name |
| Password-protected archives, encrypted files, Rights Management-protected Office files | Policy | They can't be read, so they are reported as unscannable; the policy's `on_unscannable` decides (allow, block or monitor) |
| Split, base64-encoded or otherwise obfuscated content | Accepted | Can't be detected reliably |
| PDFs with text (exported from Word, browsers, most tools) | Covered | The text of each page is read; an encrypted PDF is reported as unscannable, and text in a font the agent can't map to Unicode makes the result `truncated`, never clean |
| Images, scanned PDFs, photos of documents | Later (needs OCR) | Scanned IDs and contracts are a real accidental-leak case; text in images isn't read yet. A PDF with no text is reported as unscannable (`unsupported_type`), so `on_unscannable` decides |
| Screenshots, screen recording | Later | A separate channel |
| Print | Later | A separate channel. Print to PDF saved onto a USB stick is a file copy, so it's covered |
| Copied text | Covered | The clipboard channel |
| Files copied in the file manager (Explorer, Finder, Files) | Covered | A file copy |
| Android phones over MTP ("File transfer") | Later | **Until then:** block MTP devices with a device policy (BrainStation-23/Compliance-OS#576). A phone isn't a drive, so the file hooks don't see it |
| Bluetooth file transfer | Later | |
| AirDrop | Later | |
| WSL (`\\wsl$`, USB passed through with `usbipd`) | Later | **Until then:** block WSL USB passthrough by policy. Linux inside WSL can mount a USB stick itself |
| Virtual machines (USB passthrough, shared folders) | Later | **Until then:** list the hypervisor's processes as egress apps and block USB passthrough by policy. The device belongs to the guest |
| Command-line uploads (`scp`, `rsync`, `curl`, `git push`) | Partly | Listed as egress apps; HTTPS content is invisible without the upload proxy. On Linux with `direct_block: strict`, HTTPS to a listed site goes through the proxy even when the tool ignores the proxy setting, but a tool that doesn't trust the system CA bundle then fails for that site |
| Email clients (Outlook, Thunderbird, Mail) | Partly | Seen as egress apps, but not the recipient: internal and external mail look the same |
| Booting another operating system, removing the disk | Out of scope | Disk encryption (BitLocker, FileVault, LUKS) is the control |
| Memory-mapped writes, hard links, symlinks | Covered | Checked when the file is opened; results are tied to the file's identity |

## Blocking on Linux: what it does and doesn't hold

- **Held:** a new file created on a monitored drive or share by a copy program (`cp`, `mv`, `rsync`, `install`, `dd`, `tar`, and the common file managers). It is judged by the files that program has open for reading at that moment.
- **Not held, judged after the write:** files written by any other program (an editor's "Save as", a shell redirect, a browser download), and existing files overwritten in place. `on_close_violation` (record, quarantine or delete) applies to those.
- **Never held:** antivirus, indexers, thumbnailers and backup daemons. Backups to a USB drive with `rsync` are a copy: list backup drives as trusted devices.
- **Fails open:** a slow scan (past `scan_timeout_ms`, at most 10 seconds), a flood of opens, a crash or a stalled event loop all end in "allow", counted in the status (`files.blocking`). The emergency switch `dlp-files-off` in the config directory turns blocking off within seconds. How to use it, and how to give back a quarantined file: [dlp-file-runbook.md](dlp-file-runbook.md).

## Overrides and exceptions

- A `block_override` policy blocks, then asks the user in a dialog: continue with a reason, request an exception, or cancel. A reason lets that file through for that user for 10 minutes and is recorded as an `overridden` event; a user gets `override_daily_limit` overrides a day.
- An exception request goes to IT with the reason; once approved, it reaches the device in `modules.files.exceptions` and the file passes until the exception expires. A file edited after approval has a new hash and is checked again.
- Linux needs `zenity` or `kdialog` for the dialog; without one, the user gets the block notification only.

## When the user isn't told

A blocked or removed file shows the user a desktop notification, unless notifications don't reach them. The event's `user_notified` is then `false`, and the session's `notifications` capability says why:

| Value | Fix |
|---|---|
| `disabled:global` | The user turned off all notifications (Windows: Settings → System → Notifications) |
| `disabled:app` | The user turned off SentinelGo's notifications (Windows: Settings → System → Notifications → SentinelGo; macOS: System Settings → Notifications → Script Editor or terminal-notifier) |
| `disabled:policy` | Group Policy (`NoToastApplicationNotification`) or an MDM profile blocks them |
| `dnd` | Do Not Disturb, Focus, a full-screen app or a presentation: shown in the notification center later |
| `unavailable:no_tool`, `unavailable:no_server` | Linux: install `notify-send` (libnotify), or run a desktop with a notification server |

## Review

This list is re-reviewed at every major Windows, macOS and Linux release, since new sharing features can open new paths without notice.

Last review: 2026-11-02 (signed off on BrainStation-23/SentinelGo#338).
