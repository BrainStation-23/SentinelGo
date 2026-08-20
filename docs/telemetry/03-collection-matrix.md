# 03 — Cross-Platform Collection Matrix

*Deliverable 5: the recommended collection mechanism for every missing or weak data category.*

## Selection principles

1. **Prefer a stable native API over a repeatedly-spawned subprocess.** A PowerShell launch costs 350–900 ms cold; a native WMI query costs ~50–100 ms. At a 15-minute cadence across a fleet that difference is the whole performance budget.
2. **`CGO_ENABLED=0` is absolute.** No IOKit, no Endpoint Security Framework, no `libudev`, no kernel drivers. Everything below is pure Go or a subprocess. `make check-no-cgo` enforces it, and under `CGO_ENABLED=0` a cgo file's build constraint silently goes false and a weaker fallback compiles in — so a violation degrades functionality at runtime rather than failing the build.
3. **One subprocess for many items beats one per item.** `systemctl show '*.service'` returns every unit in a single call; `Get-PhysicalDisk | ForEach-Object { … }` handles every disk in one PowerShell launch.
4. **Record the mechanism actually used.** Every `CollectorResult` carries a `Source` string such as `wmi:root/wmi:BatteryStaticData` or `exec:smartctl`, so a silent fallback to a weaker source is visible server-side instead of looking like a normal success.
5. **Do not fabricate.** Where an OS cannot supply a value, report the capability state rather than a zero.

### Windows: native WMI or PowerShell?

Use `github.com/yusufpapurcu/wmi` (already a dependency, pure Go, precedent in `internal/osinfo/display/display_windows.go` with its `recover()` guard) when the class is plain-WQL-queryable — especially when it returns binary or array properties that PowerShell's JSON rendering mangles.

Use PowerShell when the data needs a cmdlet's object model or an ASSOCIATORS join that raw WQL makes painful: `Get-PhysicalDisk`, `Get-StorageReliabilityCounter`, `Get-ScheduledTask`, `Get-BitLockerVolume`, `Get-MpComputerStatus`, `dsregcmd`, the Windows Update COM API.

Use `golang.org/x/sys/windows/registry` (pure Go, already a dependency) instead of shelling out to `reg query`.

---

## Collection matrix

### Device identity and virtualisation

| Item | Windows | macOS | Linux |
|---|---|---|---|
| Asset tag | WMI `Win32_SystemEnclosure.SMBIOSAssetTag` | *not exposed* | read `/sys/class/dmi/id/chassis_asset_tag` |
| Device UUID | WMI `Win32_ComputerSystemProduct.UUID` | `ioreg -rd1 -c IOPlatformExpertDevice` → `IOPlatformUUID` | read `/sys/class/dmi/id/product_uuid` |
| Machine ID | registry `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` | `IOPlatformUUID` | read `/etc/machine-id` |
| Board serial | WMI `Win32_BaseBoard.SerialNumber` | *not exposed* | read `/sys/class/dmi/id/board_serial` |
| Hypervisor | WMI `Win32_ComputerSystem` Model/Manufacturer + `HypervisorPresent` | `sysctl -n kern.hv_vmm_present` | `systemd-detect-virt`, else DMI `sys_vendor` |
| Cloud platform | DMI vendor strings (Amazon EC2, Microsoft Corporation/Virtual Machine, Google) | n/a in practice | DMI `sys_vendor` / `product_name` |

Detect Hyper-V, VMware, KVM/Proxmox, VirtualBox, AWS, Azure and GCP from vendor and product strings. **Do not query cloud instance-metadata endpoints** — that is an outbound network call from every endpoint and can hang for seconds behind a proxy.

### Directory join and sessions

| Item | Windows | macOS | Linux |
|---|---|---|---|
| Domain membership | WMI `Win32_ComputerSystem.PartOfDomain`, `.Domain` | `dsconfigad -show` | `realm list`, else `/etc/sssd/sssd.conf` |
| Entra ID join | parse `dsregcmd /status` → `AzureAdJoined`, `DomainJoined`, `TenantId`, `DeviceId` | n/a | n/a |
| Logged-in sessions | WMI `Win32_LogonSession` + `Win32_LoggedOnUser`; `quser` for session type and state | `who` + `stat -f%Su /dev/console` | `loginctl list-sessions -o json`, else utmp |
| Console user | `Get-CimInstance Win32_ComputerSystem.UserName` | `stat -f%Su /dev/console` | `loginctl show-session` seat0 |
| Remote indicator | RDP session type from `quser` | SSH sessions only | `loginctl` remote flag |

### Storage, SMART and encryption

| Item | Windows | macOS | Linux |
|---|---|---|---|
| Physical disks | PowerShell `Get-PhysicalDisk` (one call) | `diskutil list -plist` | `lsblk --json -d -b -o NAME,TYPE,MODEL,SERIAL,SIZE,ROTA,TRAN` |
| Volumes | `Get-Partition` + `Get-Volume` | `diskutil info -plist <dev>` | `lsblk` hierarchy + `df -B1` |
| SMART | `Get-StorageReliabilityCounter` (Temperature, Wear, PowerOnHours, ReadErrorsTotal); native WMI `MSStorageDriver_FailurePredictStatus` / `…Data` in `root\wmi` | `smartctl` if present (Homebrew only), else `diskutil info` SMART verb | `smartctl -n standby --json=c -a <dev>` |
| BitLocker | `Get-BitLockerVolume` → ProtectionStatus, EncryptionPercentage, EncryptionMethod, **KeyProtector types** | n/a | n/a |
| FileVault | n/a | `fdesetup status`, `fdesetup haspersonalrecoverykey` | n/a |
| LUKS | n/a | n/a | `lsblk -o FSTYPE`, `cryptsetup luksDump` (header only) |

Two notes on SMART:

- **Use `-n standby`.** Without it, `smartctl` spins up a sleeping drive, which takes seconds and causes avoidable wear. The existing `smartctl -H` call lacks this flag.
- **Use `shared.RunCommandOutput`, not `RunCommand`.** smartctl signals health through exit-code bit flags, so `RunCommand` discards stdout for exactly the failing drives that matter most. `RunCommandOutput` already handles this and is the correct existing helper.

Native WMI is right for `MSStorageDriver_FailurePredictData` because it returns a 512-byte `VendorSpecific` ATA blob that PowerShell renders as a 512-element JSON number array. Decode it in Go: attributes begin at offset 2, twelve bytes each, thirty entries; ID 5 reallocated sectors, 9 power-on hours, 177/231/233 SSD wear, 187 uncorrectable, 194 temperature, 197 pending, 199 CRC errors, 241/242 LBAs written/read. This byte arithmetic is the highest-risk code in the storage work — offset errors produce plausible but wrong numbers — so it needs a fixture test.

### Battery

| Item | Windows | macOS | Linux |
|---|---|---|---|
| Design / full-charge capacity | native WMI `root\wmi` `BatteryStaticData.DesignedCapacity`, `BatteryFullChargedCapacity` | `ioreg -rc AppleSmartBattery` → `DesignCapacity`, `AppleRawMaxCapacity` | `/sys/class/power_supply/<bat>/energy_full_design` or `charge_full_design` |
| Cycle count | `BatteryStaticData.CycleCount` | `CycleCount` | `cycle_count` |
| Charging / AC state | `BatteryStatus.PowerOnline`, `.Charging` | `ExternalConnected`, `IsCharging` | `status`, plus any `Mains` supply with `online=1` |

Windows battery detail should be **100% native WMI**: four PowerShell launches would cost roughly 3 seconds against about 100 ms for the WMI queries. Note that `Win32_Battery.DesignCapacity` is almost always NULL — the real values live in the `root\wmi` classes, joined by `InstanceName`.

Two platform traps worth encoding as tests:

- **Linux units.** If `energy_*` exists the unit is µWh; otherwise `charge_*` is µAh and millwatt-hours require `(charge_µAh × voltage_µV) / 1e9`. Mixing these is the classic bug. Also enumerate `/sys/class/power_supply/*` by `type == Battery` rather than hardcoding `BAT0`/`BAT1`, which misses `CMB0`, `BATT` and `macsmc-battery`.
- **Apple silicon.** `MaxCapacity` returns `100` (a percentage) on M-series while `AppleRawMaxCapacity` holds mAh. `Temperature` is centi-Kelvin: `°C = value/100 − 273.15`.

### Network

| Item | Windows | macOS | Linux |
|---|---|---|---|
| MTU, DHCP, link state | `Get-NetIPInterface`, `Get-NetAdapter` | `ifconfig`, `ipconfig getpacket <if>` | `/sys/class/net/<if>/{mtu,operstate}` |
| Default route | `Get-NetRoute -DestinationPrefix 0.0.0.0/0` | `netstat -nr -f inet` | `ip route show default` |
| DNS | `Get-DnsClientServerAddress` | `scutil --dns` | `/etc/resolv.conf`, `resolvectl status` |
| Proxy | registry `…\Internet Settings` | `networksetup -getwebproxy <svc>` | `http_proxy` env + desktop settings |
| VPN | adapter type from `Get-NetAdapter` | `utun*` interfaces | `tun*`/`ppp*` interfaces |
| Routing table *(opt-in)* | `Get-NetRoute` | `netstat -nr` | `ip route show` |
| ARP cache *(opt-in)* | `Get-NetNeighbor` | `arp -an` | `ip neigh show` |
| Wi-Fi detail | `netsh wlan show interfaces` | `wdutil info`, `airport -I` fallback | `iw dev <if> link` |

Basic network inventory stays lightweight: interfaces, addresses, gateway, DNS, proxy and VPN status. Routing tables, ARP caches and active connections are **detailed telemetry behind their own flag**, not part of every cycle.

`airport` is deprecated in recent macOS; prefer `wdutil info` and keep `airport` as a fallback. Also memoise `networksetup -listallhardwareports`, which the existing code re-invokes four times per interface.

### Processes and persistence

| Item | Windows | macOS | Linux |
|---|---|---|---|
| Process inventory | `gopsutil/v4/process` — pure Go, no per-OS files needed | same *(verify under `CGO_ENABLED=0`)* | same |
| Run keys | `x/sys/windows/registry` across `HKLM` and every `HKEY_USERS\S-1-5-21-*` hive | n/a | n/a |
| Startup folders | `os.ReadDir` on ProgramData and per-user Start Menu | n/a | n/a |
| Scheduled tasks | `Get-ScheduledTask` + `Get-ScheduledTaskInfo`, one call | n/a | n/a |
| systemd units | n/a | n/a | `systemctl show '*.service' -p Id,ExecStart,User,FragmentPath,UnitFileState` — **one call, not N** |
| cron | n/a | read `/etc/crontab`, `/var/at/tabs/*` | read `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/*` |
| launchd | n/a | `plutil -convert json -o - <plist>` | n/a |
| XDG autostart | n/a | n/a | `/etc/xdg/autostart/*.desktop`, `~/.config/autostart` |

Practical notes:

- **CPU percentage:** use `p.CPUPercent()`, which is cheap and returns a lifetime average. `p.Percent(time.Second)` blocks a full second **per process**. Name the field `cpu_percent_avg` so the semantics are honest rather than implying an instantaneous sample.
- **Read cron files directly.** As root the spool directories are readable; `crontab -l -u <user>` would be one subprocess per user. Watch the format trap: `/etc/crontab` and `/etc/cron.d/*` carry a sixth *user* field that user crontabs do not, and `MAILTO=`/`PATH=` lines must not parse as jobs.
- **launchd plists are frequently binary** and there is no pure-Go binary-plist reader in the dependency set. `plutil -convert json -o -` is per-file, so filter aggressively first — skipping `/System/Library/*` and `com.apple.*` labels cuts 250+ files to typically 10–40.
- **Filter Windows built-in scheduled tasks by default.** `\Microsoft\Windows\*` is roughly 90% of the list; excluding it takes ~400 tasks down to ~30, cutting both runtime and payload.
- **Per-user data from a SYSTEM service:** reuse the `Registry::HKEY_USERS` idiom already proven in `software/collect_windows.go` and the `userhomes_*.go` enumeration. The service account's own `HKCU` is empty, so this is the only way to see per-user installs and autoruns.

### Patches and certificates

| Item | Windows | macOS | Linux |
|---|---|---|---|
| Installed updates | `Win32_QuickFixEngineering` *(quality updates only)* **plus** Windows Update COM `QueryHistory` | `softwareupdate --history` | `/var/log/dpkg.log`, `rpm -qa --last` |
| Pending updates | Windows Update COM `Search("IsInstalled=0")` | `softwareupdate -l` | `apt list --upgradable`, `dnf updateinfo list` |
| Last scan / last install | registry `…\WindowsUpdate\Auto Update\Results\{Detect,Install}` | `com.apple.SoftwareUpdate.plist` | package-manager log timestamps |
| Reboot required | registry triple: `CBS\RebootPending`, `WindowsUpdate\…\RebootRequired`, `PendingFileRenameOperations` | inferred from pending updates | `/var/run/reboot-required`, `needs-restarting -r` |
| Certificates | `Cert:\LocalMachine\*` or the cert-store API via `x/sys/windows` | `security find-certificate -a -p` | parse `/etc/ssl/certs` with `crypto/x509` |

`Win32_QuickFixEngineering` alone is not sufficient: it covers quality updates and misses feature updates, driver updates and Store updates entirely. The patch model must carry installed, pending and history separately, with categories.

Certificates carry **subject, issuer, thumbprint, validity dates and key usage only** — never private keys.

---

## Summary of native-API migrations worth making

| Change | Benefit |
|---|---|
| Native WMI for battery (`root\wmi` classes) | ~3 s → ~100 ms |
| Native WMI for `MSStorageDriver_FailurePredictData` | correct binary decoding; PowerShell mangles the byte array |
| `x/sys/windows/registry` instead of `reg query` | no subprocess per key read |
| `ioreg` instead of `system_profiler` where equivalent | ~1.5–4 s → ~30 ms |
| One `systemctl show '*.service'` instead of per-unit calls | N subprocesses → 1 |
| Direct cron-file reads instead of `crontab -l -u` | N subprocesses → 0 |

Migrating *existing* collectors to these mechanisms would change working code and is therefore recorded in [06-existing-code-observations.md](06-existing-code-observations.md) rather than assumed. New collectors use them from the start.
