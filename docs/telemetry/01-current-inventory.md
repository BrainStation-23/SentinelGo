# 01 — Current Telemetry Inventory

*Deliverables 1–2: what SentinelGo collects today, where it comes from, how often, and whether it reaches the backend.*

This document is a factual audit of the code as it stands. It is the baseline for [02-gap-analysis.md](02-gap-analysis.md).

> **Note on stale documentation.** Several existing docs describe an architecture this repo does not have. `CLAUDE.md` referenced `internal/heartbeat/`, `cmd/auditlogs/`, a `supabase/` directory and SQL migrations — none of which exist in the repo or in its 144-commit history. `docs/PROJECT_CONTEXT.md`, `docs/02-config-module.md`, `docs/audit-logs-flow.md` and `process_flow.md` contain further drift (env-var configuration that nothing reads, an `agent-refresh` endpoint that does not exist, encryption-at-rest that is not implemented). `CLAUDE.md` has been corrected; the others are flagged in [06-existing-code-observations.md](06-existing-code-observations.md).

---

## 1. Actual architecture

```
cmd/sentinelgo/            CLI, service lifecycle
internal/
  osinfo/                  inventory collectors, one sub-package per domain
    shared/                SystemInfo types + RunCommand/ReadFileContent helpers
    audio,cpu,disk,display,gpu,network,peripherals,printers,ram,security,system,users
  service/
    agent/                 inventory upload  -> agent_enqueue_inventory
    software/              software inventory -> agent_enqueue_software
    services/              service inventory  -> agent_enqueue_services
    auditlog/              audit log upload   -> agent_enqueue_audit_logs
    auth/                  agent-login, JWT refresh, circuit breaker
    task/                  remote task execution
    rpcutil/               shared enqueue retry + response types
  auditlogs/collector/     OS event log collection (per-platform)
  logging/                 collector -> parser -> SQLite queue -> uploader
  scheduler/               task registry and periodic runner
  store/                   local SQLite (software, services, audit logs, tasks)
  telemetry/               NEW: enterprise telemetry layer (Phase B)
  updater/                 Supabase Storage + RPC self-update
```

The backend is **not in this repository**. It is a Supabase project reached over HTTP.

### Backend surface

| Endpoint | Kind | Caller |
|---|---|---|
| `POST /functions/v1/agent-login` | Edge Function (the only one) | `service/auth/login.go` |
| `POST /rest/v1/rpc/agent_enqueue_inventory` | Postgres RPC | `service/agent/agent.go` |
| `POST /rest/v1/rpc/agent_enqueue_software` | Postgres RPC | `service/software/sync.go` |
| `POST /rest/v1/rpc/agent_enqueue_services` | Postgres RPC | `service/services/sync.go` |
| `POST /rest/v1/rpc/agent_enqueue_audit_logs` | Postgres RPC | `service/auditlog/auditlog.go` |
| `POST /rest/v1/rpc/agent_get_tasks` / `agent_update_task` | Postgres RPC | `taskstore/client.go` |
| `POST /rest/v1/rpc/get_latest_agent_release` | Postgres RPC | `updater/checker.go` |
| `PATCH/GET /rest/v1/agents` | PostgREST table | `service/agent/agent.go` |
| `GET /storage/v1/object/agent-releases/…` | Storage | `updater/downloader.go` |

The `msg_id`/`queue` response shape indicates a pgmq-style message queue rather than direct table writes.

---

## 2. Collection mechanism summary

Nearly all telemetry is **shell-out based**. `gopsutil/v4` appears in only about five non-test files. Every osinfo subprocess funnels through two helpers in `internal/osinfo/shared/helpers.go`, both with a 30-second timeout and NUL-byte stripping:

- `RunCommand(name, args...) (string, error)` — discards stdout on non-zero exit.
- `RunCommandOutput(name, args...) (string, int, error)` — returns the exit code, for tools like `yum check-update` that signal state that way.

One deliberate exception: `disk_linux.go` calls `exec.CommandContext` directly for `smartctl -H` with a 5-second timeout, because smartctl signals health through exit-code bit flags that `RunCommand` would treat as failure.

`internal/osinfo/display/display_windows.go` is the only file using **native WMI** (`github.com/yusufpapurcu/wmi`) rather than PowerShell, guarded by `recover()`. It is the precedent for the native-API direction in [03-collection-matrix.md](03-collection-matrix.md).

---

## 3. What is collected, by domain

### Device identity and hardware — `internal/osinfo/system/`, `collect.go`

| Data | Windows | macOS | Linux |
|---|---|---|---|
| Hostname, uptime | `gopsutil host.Info()` | same | same |
| Serial number | `Win32_BIOS`, `Win32_ComputerSystemProduct`, `Win32_BaseBoard` (PowerShell) | `system_profiler SPHardwareDataType -json`, `ioreg` fallback | `/sys/class/dmi/id/*`, `dmidecode` fallback |
| Hardware model | `Win32_ComputerSystem.Model` | `system_profiler` | `/sys/class/dmi/id/product_name` |
| Chassis type | `Win32_SystemEnclosure.ChassisTypes` | derived from model string | `/sys/class/dmi/id/chassis_type` |
| FQDN | `[System.Net.Dns]::GetHostEntry` | `hostname -f` | `hostname -f` |
| Firmware (type/vendor/version) | `Win32_BIOS`; type hardcoded `"UEFI"` | `system_profiler` boot ROM; vendor hardcoded `"Apple"` | `/sys/firmware/efi` probe + `/sys/class/dmi/id/bios_*` |
| TPM version | `Win32_Tpm` (root/cimv2/security) | `SPiBridgeDataType` | `/sys/class/tpm/tpm0/*` |
| Battery condition (string only) | `Win32_Battery.BatteryStatus` code | `SPPowerDataType`, `pmset -g batt` | `/sys/class/power_supply/BAT0\|BAT1` |

`SystemInfo.LastRestart` is declared but never assigned.

### CPU / memory / GPU / display / audio / printers / peripherals

| Domain | Mechanism |
|---|---|
| CPU | `gopsutil` only — `cpu.Info()`, `cpu.Percent(1s, false)` (**blocks one second**), `cpu.Counts()` |
| Memory | `gopsutil mem.VirtualMemory()`; modules via `Win32_PhysicalMemory` / `dmidecode -t memory` / `SPMemoryDataType` |
| GPU | `Win32_VideoController` / `lspci` + `nvidia-smi` + `rocm-smi` + sysfs / `SPDisplaysDataType` |
| Displays | **native WMI** `WmiMonitorID` / EDID parsing from `/sys/class/drm` / `SPDisplaysDataType` |
| Audio | `Get-PnpDevice` AudioEndpoint / `lspci` + `cat /proc/asound/cards` / `SPAudioDataType` |
| Printers | `Get-Printer` (falls back to **`wmic`**, removed in Win11 24H2+) / `lpstat -p` + `cups` / `lpstat` + `SPPrintersDataType` |
| Peripherals (USB/BT/HID) | `Get-PnpDevice` filtered by class / `/proc/bus/input/devices` + `lsusb` + `bluetoothctl` / `SPUSBDataType`, `SPBluetoothDataType`, `ioreg` |

### Storage — `internal/osinfo/disk/`

Windows uses `Get-PhysicalDisk`, then **per disk** a second PowerShell call combining `Get-Partition`, `Win32_LogicalDisk` and `Get-BitLockerVolume`. Linux uses `lsblk --json`, `dmsetup`, `sedutil-cli`, `df`, plus `smartctl -H`. macOS uses `SPStorageDataType`, `fdesetup status` and `SPiBridgeDataType`.

**Physical disks and their partitions are conflated in one `DiskDevice` struct** — it carries both `Capacity`/`SerialNumber`/`InterfaceType` and `DriveLetter`/`MountPoint`/`FileSystem`. This is a modelling defect addressed in [02-gap-analysis.md](02-gap-analysis.md).

### Network — `internal/osinfo/network/`

Base enumeration via `gopsutil psnet.Interfaces()`, then per-platform hooks for speed, gateway, DNS, Wi-Fi (`netsh wlan show interfaces` / `iw dev link` / `airport -I`). `IPv4Address.IsDHCP` is declared but never set. On macOS `networksetup -listallhardwareports` is re-invoked inside four separate hooks with no memoisation — four subprocesses per interface.

### Security posture — `internal/osinfo/security/`

The strongest existing domain, with nine sub-structs: firewall state and profiles, antivirus (SecurityCenter2 / systemd probes / path probes plus Gatekeeper, XProtect, MRT), EDR/XDR detection (16 known Windows services, 5 Linux, 7 macOS paths), kernel hardening (VBS, HVCI, SIP, SELinux, AppArmor, lockdown), device encryption, hardware security (TPM, Secure Boot, Secure Enclave), identity/access controls (Windows Hello, Credential Guard, UAC, SSH config, sudo), network exposure (listening ports via `gopsutil net.Connections`, capped at 200), and a computed posture summary.

### Software inventory — `internal/service/software/`

Windows registry uninstall keys **across every loaded user hive** (`Registry::HKEY_USERS` matching `^S-1-5-21-`), `Get-AppxPackage`; Linux `dpkg-query`, `rpm`, `snap`, `flatpak`; macOS `SPApplicationsDataType`, `brew list`, `mdls` for last-opened. Browser extensions for Chrome, Firefox, Edge and Brave are scanned from `manifest.json` across all user home directories.

A SQLite catalog (`internal/store/software.go`) accrues `first_seen_at` and supports a guarded prune: a partial scan never deletes.

### Services — `internal/service/services/`

`Win32_Service` / `systemctl list-units` + `list-unit-files` / `launchctl list`, normalised to closed enums before upload.

### Audit logs — `internal/auditlogs/`, `internal/logging/`

The most mature pipeline. Windows uses **direct `wevtapi.dll` syscalls** (`EvtQuery`, `EvtNext`, `EvtRender`, `EvtSubscribe`) across 12 channels; Linux uses `journalctl -o json` plus file tailing with inode-based rotation detection; macOS uses `log show --style ndjson` plus crash-report scanning. It has a durable SQLite queue, deduplication, batching at 100, a 900 KB payload guard with recursive splitting, checkpointing, and a real-time `Subscribe()` path.

---

## 4. Frequency and delivery

| Task | Interval | Sends to | Change detection |
|---|---|---|---|
| `token-refresh` | 1 min | `agent-login` | n/a |
| `agent-info-update` | **5 min** | `agent_enqueue_inventory` | whole-payload SHA-256, 1 h force-resend, **in memory only** |
| `software-sync` | **5 min** | `agent_enqueue_software` | whole-list SHA-256, 1 h force-resend |
| `services-collect` | **5 min** | `agent_enqueue_services` | SHA-256 excluding volatile fields, 1 h force-resend |
| audit log collect+upload | 5 min | `agent_enqueue_audit_logs` | durable queue + dedup hash |
| `auto-update` | 1 h | `get_latest_agent_release` | n/a |
| task poll | 5 min | `agent_get_tasks` | n/a |

**Documentation drift:** the struct comment and `docs/02-config-module.md` claim `agent_info_update_interval` defaults to 1 h; the actual runtime default in both `Load()` and the getter is **5 minutes**.

---

## 5. Collected but never uploaded

`AgentUpdatePayload` omits several fields that `osinfo.Collect()` populates:

`Timestamp`, `Uptime`, `CPU` (the usage summary — only `CPUInfoDetailed` is sent, as `cpu_info`), `Memory`, `Disk`, `Network` (IO counters), `MACAddress`, `OSQueryVersion`, `LastRestart`.

So **CPU, memory and disk utilisation are collected every five minutes and discarded.** Device-health reporting (P3) can reuse this collection rather than adding new work.

---

## 6. Transport characteristics

| Feature | Inventory | Software | Services | Audit logs |
|---|---|---|---|---|
| Batching | No | No | No | Yes (100/batch) |
| Payload size guard | **None** | **None** | **None** | Yes (900 KB, recursive split) |
| Compression | **None anywhere** | | | |
| Offline buffer | No | Catalog only | Catalog only | **Yes** (durable queue) |
| Retry | shared `rpcutil.WithEnqueueRetry` | same | same | same |

`WithEnqueueRetry` treats 2xx as success, propagates 401, retries 5xx with exponential backoff — and **logs and drops any other 4xx**. An oversized inventory payload therefore fails permanently and silently.

---

## 7. Change detection today

`sysInfoFingerprint` ([scheduler.go:39](../../internal/scheduler/scheduler.go#L39)) hashes 23 stable fields into a single SHA-256, deliberately excluding volatile CPU/memory/disk/uptime values. Three consequences:

1. **All-or-nothing.** One changed field re-sends the entire payload, including unchanged security, peripheral and network data.
2. **In-memory only.** `agentLastHash` is a package variable, so every agent restart re-uploads everything.
3. **`DiskDevice.FreeCapacity` is inside the hash** and changes constantly, so the fingerprint is less stable than intended.

The new telemetry layer implements per-section, disk-persisted reconciliation for its own sections. The legacy path is unchanged; migrating it is [06-existing-code-observations.md](06-existing-code-observations.md) item 7.
