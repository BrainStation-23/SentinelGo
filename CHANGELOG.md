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

- AutoRun/AutoPlay and application-control state in the inventory payload, for the server's CIS, ISO 27001 and NIST CSF checks. `security_info.autorun` reports `autorun_disabled` and `autoplay_disabled` on Windows, from the AutoRun policies and each signed-in user's AutoPlay setting. `security_info.application_control` reports the strongest product and its mode (`enforced`, `audit` or `off`): WDAC and AppLocker on Windows, Gatekeeper on macOS and fapolicyd on Linux. WDAC is read from its user-mode status, because the kernel-mode status also counts Windows 11's built-in driver blocklist. AppLocker rules count only while the Application Identity service is running. A value the agent can't read is left out (#178).
- Average CPU usage in the inventory payload, for the server's device energy estimate. Each upload carries a `power_telemetry` object covering the whole time since the previous successful upload: `window_start`, `window_end`, `samples` (agent-info ticks in the window, roughly the time the machine was awake) with `sample_interval_seconds`, and `cpu_usage_avg_percent`. The average comes from CPU time counters read on every agent-info tick, including ticks that don't upload. A failed upload keeps adding to the window, so no time is lost. The object isn't part of the change check, so inventory isn't uploaded more often. It is left out until the first interval after the agent starts has completed (#198).

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

[Unreleased]: https://github.com/BrainStation-23/SentinelGo/compare/v3.6.0...HEAD
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
