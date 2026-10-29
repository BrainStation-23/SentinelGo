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

[Unreleased]: https://github.com/BrainStation-23/SentinelGo/compare/v3.7.2...HEAD
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
