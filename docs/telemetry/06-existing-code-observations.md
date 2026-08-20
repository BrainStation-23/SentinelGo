# 06 — Observations on Existing Code

**Nothing in this document has been changed. Every item requires explicit approval before anyone edits the subsystem.**

The telemetry layer is additive by design: the existing scheduler, collectors, stores, transport, authentication, software/services pipelines and audit-logging pipeline are treated as stable foundations. The findings below were surfaced during the analysis and are recorded so they are not lost — not because they are in scope.

Each item states the observation, why it matters, and a proposed fix.

---

## 1. Software collection cadence — the largest fleet-scalability item

**Observation.** `software-sync` runs a **full scan every 5 minutes**: registry enumeration across every loaded user hive, `Get-AppxPackage -AllUsers`, `system_profiler SPApplicationsDataType` (1.5–4 s), dpkg/rpm/snap/flatpak queries, browser-extension filesystem scans across all user home directories, and batched `mdls` calls.

That is 288 full scans per device per day — roughly **2.9 million scans per day across 10,000 endpoints** — for data that typically changes a few times a week.

Compounding it, `hashSoftwareList` hashes `SoftwareInfo` **wholesale, including `LastOpened`**. A last-used timestamp change on any single application forces a full re-upload of the entire software list. This is inconsistent with `hashServiceList`, which deliberately excludes volatile fields with the comment that they *"change on every restart without representing a meaningful configuration change"*.

**Why it matters.** Wasted CPU and disk I/O on every endpoint, and far more backend traffic than the 1-hour force-resend implies.

**Proposed fix.** Raise the `update_interval` default to 6 hours with a 24-hour reconcile, and exclude `LastOpened` from the software hash. The on-demand `sync-software` remote task already covers immediate refresh after a deployment. Both changes are small and reversible.

**Risk if applied:** low. **Risk if not applied:** the single largest avoidable cost in the fleet.

---

## 2. `audit_log_queue` has no retention cap

**Observation.** `internal/store/auditlogs.go` creates `audit_log_queue` with no age, row-count or size bound. Rows are deleted only on successful upload.

**Why it matters.** An agent that is offline or whose backend rejects its payloads grows this table without limit until the disk fills.

**Proposed fix.** Apply the same three-axis bounds the new telemetry queue uses — 72 hours, 5,000 rows, 64 MiB — with oldest-lowest-priority eviction and a counter so loss is visible.

---

## 3. Duplicate and wasteful collection

| Observation | Cost |
|---|---|
| `fdesetup status` runs **twice** per cycle on macOS (`disk_darwin.go` and `security_darwin.go`) | one redundant subprocess |
| TPM collected twice by different commands (`system.GetTPMVersion` vs `security.collectHardwareSecurity`) | two subprocesses, **and the two can disagree** |
| Secure Boot collected twice with inconsistent casing conventions | inconsistent values for the same fact |
| `getHardwareModel()` re-shells in `service/agent/agent.go` although `sysInfo.HardwareModel` is already populated | one redundant PowerShell / `system_profiler` call per cycle |
| `network_darwin.go` re-runs `networksetup -listallhardwareports` inside four separate hooks with no memoisation | **four subprocesses per interface** |
| `audio_linux.go` shells out to `cat /proc/asound/cards` instead of reading the file | one avoidable subprocess |

**Proposed fix.** Collect each fact once and share it; memoise the macOS hardware-port map; read the file directly. Each is contained, but each edits a working collector.

---

## 4. Context cancellation debt

**Observation.** `osinfo.Collect()` takes no `context`. The scheduler wraps it in a 90-second timeout by running it in a goroutine, so on timeout the goroutine is **abandoned rather than cancelled** and its subprocesses keep running.

**Why it matters.** A hung collector leaks a goroutine and its child processes on every cycle. Adding more subprocess-based collectors makes this worse.

**Proposed fix, incremental rather than big-bang.** Add `osinfo.CollectContext(ctx)` alongside `Collect()`, and `shared.RunCommandContext` alongside `RunCommand`, without modifying either existing function. Migrate the most expensive collectors — `security`, the `system_profiler` paths, `smartctl` — first, and migrate any collector touched for another reason as part of that change.

The new telemetry layer already takes `ctx` throughout, so the debt does not grow.

---

## 5. Credentials stored in plaintext

**Observation.** `config.json` holds `access_token`, `refresh_token` and `agent_secret` in cleartext, protected only by filesystem permissions (0600 on Unix, a SYSTEM/Admins DACL on Windows). `process_flow.md` claims *"Tokens encrypted at rest via `EncryptSensitiveData()`"* — **no such function exists anywhere in the repository.**

**Why it matters.** Any process running as the agent's user, and any backup or disk image, yields working credentials. The false documentation is arguably worse than the gap, because it prevents the risk from being noticed.

**Proposed fix.** Either implement platform-native protection (DPAPI on Windows, Keychain on macOS, kernel keyring or a file key on Linux — all achievable without cgo via `x/sys`), or correct the documentation to state the actual protection model. **Correcting the documentation should happen regardless**, and is the more urgent of the two.

Unrelated to telemetry; recorded because it was found during the audit.

---

## 6. Latent bugs and dead fields

| Observation | Effect |
|---|---|
| `disk.Usage("/")` hardcoded in `osinfo/collect.go` | wrong volume on Windows |
| `SystemInfo.LastRestart` declared, never assigned | always empty on the wire |
| `GPU.BIOSVersion` never set on any platform | always empty |
| `IPv4Address.IsDHCP` never set | always `false`, indistinguishable from a real static address |
| `printers_windows.go` falls back to `wmic` | **`wmic` is removed in Windows 11 24H2+**, so the fallback fails silently on current builds |
| `sysInfoFingerprint` hashes `DiskDevice.FreeCapacity` | free space changes constantly, so the fingerprint is far less stable than intended and forces avoidable full re-uploads |
| `EdgeFunctionURL` config field declared and documented, never read | dead configuration |
| `agent_secret` is not covered by `validateConfig()` | a config without it passes validation but can never log in |

The `FreeCapacity` item is the most consequential: it means the legacy inventory re-uploads more often than its design intends, on every device.

---

## 7. Legacy fingerprint migration

**Observation.** `sysInfoFingerprint` hashes 23 fields into one SHA-256, `agentInfoForceResend` re-sends everything hourly, and `agentLastHash` is a package variable that resets on restart.

**Why it matters.** One changed field re-sends the entire payload; every agent restart re-sends everything.

**Proposed fix.** Move the legacy inventory onto the same per-section reconciliation the new layer uses, with state persisted in `telemetry_section_state`.

**This is the largest item here and is deliberately last.** It should not be attempted until the new layer has been proven in production, and it depends on the backend supporting section-merge semantics.

---

## 8. Stale documentation

| File | Drift |
|---|---|
| `CLAUDE.md` | **Corrected in Phase A.** Previously described `internal/heartbeat/`, `cmd/auditlogs/`, a `supabase/` directory and SQL migrations that have never existed; GitHub Releases updates (actually Supabase Storage + RPC); gopsutil v3 (actually v4) |
| `docs/PROJECT_CONTEXT.md` | Documents env-var configuration that nothing reads; an `agent-refresh` endpoint that does not exist; an `agent-login` request shape that does not match the code |
| `docs/02-config-module.md` | States `agent_info_update_interval` defaults to 1 h; the actual default is **5 minutes** in both `Load()` and the getter |
| `docs/audit-logs-flow.md` | References `agent_insert_audit_logs_batch`, which does not exist |
| `process_flow.md` | Claims encryption at rest that is not implemented (see item 5); references `tenant_id` and `heartbeat_interval`, neither of which exists |

**Proposed fix.** Correct or clearly mark each as stale. Documentation that describes a system that does not exist actively misleads anyone planning against it — the analysis behind this work had to be redone once for exactly that reason.
