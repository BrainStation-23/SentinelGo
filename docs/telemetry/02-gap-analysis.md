# 02 — Gap Analysis and Platform Support Matrix

*Deliverables 3–4: what is missing against enterprise endpoint-management expectations, and what each OS can actually provide.*

Baseline: [01-current-inventory.md](01-current-inventory.md).

**Ground rule:** where an operating system genuinely does not expose a data point, this document says so. The agent must never fabricate a value or leave a field silently empty — that is what the capability manifest and `CollectorResult` in [04-architecture.md](04-architecture.md) exist to communicate.

Legend: **✅ present** · **◐ partial** · **❌ missing** · **n/a** not available on that OS

---

## 1. Gap summary by category

| # | Category | Status | Notes |
|---|---|---|---|
| 1 | Device identity | ◐ | Serial, model, chassis, FQDN present. **Missing:** asset tag, device UUID, machine ID, board serial, **physical-vs-virtual and hypervisor detection** |
| 2 | Operating system | ◐ | Name, version, build, kernel, locale, timezone, boot time present. **Missing:** install date, **pending reboot**, activation/licensing, end-of-support |
| 3 | CPU | ✅ | Complete enough. Socket count and max clock speed would be additive |
| 4 | Memory | ✅ | Total/used/free plus per-module detail already collected |
| 5 | Storage inventory | ◐ | **Physical disks and partitions share one struct.** Missing firmware version, and SMART is a one-word health string |
| 6 | Disk encryption | ◐ | Device-level status present. **Missing:** per-volume detail, encryption percentage, **key protector types**, recovery-key escrow status |
| 7 | BIOS / UEFI | ◐ | Vendor and version present. Missing release date; boot mode hardcoded on two platforms |
| 8 | TPM / secure hardware | ◐ | Version and enabled state present, **collected twice by different commands that can disagree** |
| 9 | Battery | ◐ | A single condition string. **Missing:** design/full-charge capacity, cycle count, health %, AC state |
| 10 | GPU / display | ✅ | Strong, including EDID parsing on Linux |
| 11 | Network adapters | ◐ | **Missing:** MTU, DHCP state (declared, never set), physical-vs-virtual classification |
| 12 | Wi-Fi | ◐ | SSID, signal, band present. **Missing:** BSSID, channel, authentication and encryption type |
| 13 | Routing / network config | ❌ | Default gateway and DNS present. **Missing:** routing table, proxy configuration, VPN detection, ARP cache |
| 14 | Installed software | ✅ | Genuinely strong — multi-user, multi-source, with a guarded prune |
| 15 | Software usage | ◐ | Last-opened on Windows and macOS only |
| 16 | **Running processes** | ❌ | Not collected. `internal/procinfo` finds only SentinelGo's own processes |
| 17 | Services / daemons | ✅ | Complete |
| 18 | **Startup / persistence** | ❌ | No Run keys, scheduled tasks, cron, LaunchAgents or autostart entries |
| 19 | User accounts | ◐ | Local accounts and groups present. **Missing:** enabled/disabled state, last login, password age, admin/sudo flag |
| 20 | **Sessions** | ❌ | No logged-in user, console user, session type or login time |
| 21 | **Directory join** | ❌ | No domain, Active Directory or Entra ID join status |
| 22 | Security posture | ✅ | The strongest domain. Screen-lock policy is the notable omission |
| 23 | **Patch / update state** | ◐ | **A count of missing updates only** — no installed list, no history, no categories |
| 24 | Peripherals | ◐ | Present; missing device class and connected/disconnected state |
| 25 | Printers | ◐ | Present; missing port, default flag, real status. DPI is guessed from driver names |
| 26 | Browsers | ◐ | Derivable from existing software inventory; no classification pass yet |
| 27 | Management/security agents | ✅ | EDR/XDR detection across all three platforms |
| 28 | Device health | ◐ | **Collected every 5 minutes and discarded** — never uploaded |
| 29 | System events | ❌ | OS log forwarding exists; no agent-asserted state-change events |

---

## 2. Platform support matrix for the missing items

### Device identity and context

| Item | Windows | macOS | Linux |
|---|---|---|---|
| Asset tag | ✅ `Win32_SystemEnclosure.SMBIOSAssetTag` | ❌ not exposed by Apple firmware | ✅ `/sys/class/dmi/id/chassis_asset_tag` |
| Device UUID | ✅ `Win32_ComputerSystemProduct.UUID` | ✅ `IOPlatformUUID` via `ioreg` | ✅ `/sys/class/dmi/id/product_uuid` (root only) |
| Machine ID | ✅ registry `MachineGuid` | ✅ `IOPlatformUUID` | ✅ `/etc/machine-id` |
| Board serial | ✅ `Win32_BaseBoard` | ❌ not separately exposed | ✅ `/sys/class/dmi/id/board_serial` |
| **Hypervisor detection** | ✅ `Win32_ComputerSystem` model/manufacturer | ◐ `sysctl kern.hv_vmm_present` (guest only) | ✅ `systemd-detect-virt`, DMI vendor |
| **Domain / AD join** | ✅ `Win32_ComputerSystem.PartOfDomain` | ✅ `dsconfigad -show` | ◐ `realm list` / sssd, only when joined |
| **Entra ID / Azure AD join** | ✅ `dsregcmd /status` | n/a | n/a |
| **Logged-in sessions** | ✅ `Win32_LogonSession`, `quser` | ◐ `who`, `stat /dev/console` — no RDP concept | ✅ `loginctl list-sessions -o json`, utmp |
| Remote session indicator | ✅ RDP session state | ◐ SSH only | ✅ SSH and remote X |

### Storage and encryption

| Item | Windows | macOS | Linux |
|---|---|---|---|
| Physical/volume separation | ✅ `Get-PhysicalDisk` + `Get-Partition` | ✅ `diskutil list -plist` | ✅ `lsblk` hierarchy |
| Disk firmware version | ✅ `MSFT_PhysicalDisk.FirmwareVersion` | ◐ `smartctl` only, not installed by default | ✅ `smartctl`, `/sys/block/*/device/rev` |
| **SMART attributes** | ✅ `Get-StorageReliabilityCounter`, `MSStorageDriver_FailurePredictData` | ◐ `diskutil` health verb only; Apple silicon NVMe exposes very little | ✅ `smartctl --json` (needs the package) |
| Encryption percentage | ✅ `Get-BitLockerVolume.EncryptionPercentage` | ◐ `fdesetup` reports state, not percentage | ❌ LUKS has no notion of partial encryption |
| **Key protector types** | ✅ `Get-BitLockerVolume.KeyProtector` | ◐ institutional/personal recovery key presence | ◐ `cryptsetup luksDump` key slots |
| Recovery key escrow status | ✅ AD/Entra backup status | ✅ `fdesetup haspersonalrecoverykey` | ❌ no standard escrow concept |

> Recovery **keys** are never transmitted anywhere. Only availability and escrow status.

### Network

| Item | Windows | macOS | Linux |
|---|---|---|---|
| MTU | ✅ `Get-NetIPInterface` | ✅ `ifconfig` | ✅ `/sys/class/net/*/mtu` |
| DHCP state | ✅ `Get-NetIPInterface.Dhcp` | ✅ `ipconfig getpacket` | ◐ NetworkManager or lease-file inspection |
| Proxy configuration | ✅ registry `ProxySettings`, WPAD | ✅ `networksetup -getwebproxy` | ◐ env vars and per-desktop settings; no single source |
| VPN detection | ✅ adapter type | ✅ `utun` interfaces | ◐ `tun`/`ppp` interface heuristics |
| Routing table | ✅ `Get-NetRoute` | ✅ `netstat -nr` | ✅ `ip route show` |
| ARP / neighbour cache | ✅ `Get-NetNeighbor` | ✅ `arp -an` | ✅ `ip neigh show` |
| Wi-Fi BSSID / channel / auth | ✅ `netsh wlan show interfaces` | ◐ `airport -I` (deprecated in recent macOS; needs `wdutil` fallback) | ✅ `iw dev link` |

Wi-Fi **passwords are never collected** on any platform.

### Processes, persistence, patches, certificates

| Item | Windows | macOS | Linux |
|---|---|---|---|
| Process inventory | ✅ `gopsutil` (pure Go) | ✅ `gopsutil` — **verify under `CGO_ENABLED=0`**, see below | ✅ `gopsutil` / `/proc` |
| Process owner | ✅ | ◐ may need `ps` enrichment | ✅ |
| Startup: Run keys | ✅ registry, all user hives | n/a | n/a |
| Startup: scheduled tasks | ✅ `Get-ScheduledTask` | ◐ `launchd` `StartCalendarInterval` | ✅ systemd timers, cron |
| Startup: LaunchAgents/Daemons | n/a | ✅ plists (often binary — use `plutil -convert json`) | n/a |
| Startup: cron | n/a | ✅ `/etc/crontab`, `/var/at/tabs` | ✅ `/etc/cron*`, `/var/spool/cron` |
| Startup: login items | ◐ startup folders | ❌ modern store is an undocumented binary format needing a GUI session — **documented as unavailable** | ✅ XDG autostart |
| Installed patch list | ✅ `Win32_QuickFixEngineering` (quality updates only) + Windows Update COM for the rest | ✅ `softwareupdate --history` | ✅ `/var/log/dpkg.log`, `rpm -qa --last` |
| Pending updates | ✅ Windows Update COM | ✅ `softwareupdate -l` | ✅ `apt list --upgradable`, `dnf updateinfo` |
| Update categories (quality/feature/driver) | ✅ | ◐ limited | ◐ security-vs-other only |
| Reboot required | ✅ registry triple | ◐ inferred from pending updates | ✅ `/var/run/reboot-required` |
| Certificates | ✅ `Cert:\LocalMachine` / cert-store API | ✅ `security find-certificate -a -p` | ✅ `/etc/ssl/certs` + `crypto/x509` |
| Screen-lock policy | ✅ registry / `net accounts` | ✅ `sysadminctl`, `pmset` | ◐ desktop-environment specific |

> **`gopsutil` on macOS under `CGO_ENABLED=0`:** gopsutil has historically had cgo-backed paths on Darwin behind build tags. Under `CGO_ENABLED=0` a cgo file's constraint silently evaluates false and a weaker fallback compiles in — the exact silent-degradation failure mode the no-cgo rule warns about. Before shipping the process collector, verify on real macOS hardware that `p.Cmdline()` and `p.Username()` return non-empty values; if not, add Darwin-only enrichment via `ps -axo pid,ppid,user,comm,args`.

---

## 3. Structural gaps (not data points)

These are defects in how telemetry is modelled and delivered. They limit what can be added, which is why the foundation work precedes new collectors.

1. **Change detection is all-or-nothing, in-memory, and time-coupled.** One changed field re-sends everything; every restart re-sends everything; a global one-hour force-resend applies the same cadence to a serial number and a firewall state.
2. **Physical disks and partitions share one struct**, so "how full is C:" and "is this NVMe failing" cannot be modelled independently.
3. **No payload size guard on inventory, software or services.** Oversize produces a 4xx that the shared retry policy logs and drops — permanent, silent data loss.
4. **No way to distinguish "absent" from "failed".** A device with no TPM and a device whose TPM query crashed both report an empty field.
5. **No collection status or timing**, so a collector that has been failing for a week is invisible.
6. **No compression anywhere.**
7. **`osinfo.Collect()` takes no `context`**, so the scheduler's 90-second timeout abandons the goroutine while its subprocesses keep running.
8. **Health metrics are collected and discarded** every five minutes.

Items 1, 3, 4, 5 and 8 are addressed by the Phase B foundation. Items 2 and 6 are addressed in later phases. Item 7 is deliberately deferred — see [06-existing-code-observations.md](06-existing-code-observations.md).

---

## 4. Deliberately out of scope

Per the project brief, this phase does **not** collect: passwords or credential material, browser history, cookies or saved passwords, document contents, messages, keystrokes, screenshots, or clipboard contents. DLP — file-activity monitoring, content inspection and device-control enforcement — is entirely out of scope; the architecture only avoids foreclosing it later.
