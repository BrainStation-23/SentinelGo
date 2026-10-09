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

[Unreleased]: https://github.com/BrainStation-23/SentinelGo/compare/v3.3.0...HEAD
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
