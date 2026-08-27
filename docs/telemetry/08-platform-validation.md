# 08 — Linux and macOS Validation Procedure

**Status: not yet performed.** This document is the procedure, not a result.
Nothing in it records an outcome, and no outcome may be recorded here that was
not produced by running these commands on real hardware.

---

## 1. What has and has not been verified

| Verified | How | Covers |
|---|---|---|
| Compiles for every target | `CGO_ENABLED=0 GOOS=… GOARCH=… go build ./...` on linux/darwin/windows × amd64/arm64 | Syntax, types, build tags, imports |
| Parsers produce the right model | Unit tests against captured command output, in OS-neutral `parse.go` files | The `parseIPRoute`, `parseNetstatRoutes`, `parse*` logic for every collector |
| Collectors run correctly on Windows | Full `go test ./...` on windows/amd64, plus a real collection cycle that populated 20 of the 22 sections | The `_windows.go` paths |

| **Not verified** | Why it matters |
|---|---|
| The `_linux.go` and `_darwin.go` command paths | **~1,900 lines that have never executed.** Compilation proves the code is well-formed; it proves nothing about whether `dsregcmd`, `loginctl`, `diskutil`, `ioreg`, `fdesetup`, `system_profiler`, `nmcli`, `netstat` or `ip` are present, whether they need elevation, or whether their real output matches what the parser tests assume |
| Capability reporting on those platforms | A collector that fails on a real host should report `unsupported`, not `supported` with empty data |
| Real collection timings | The per-collector cost estimates in [05-impact-and-roadmap.md](05-impact-and-roadmap.md) are estimates |

**A cross-compile is not a runtime validation, and this document exists so that
distinction is never quietly lost.**

## 2. Prerequisites

- A real machine or VM per platform — **not** a container. Containers hide the
  systemd, launchd, DMI and hardware surfaces most of these collectors read.
- **Elevation on every platform** — root/sudo on Linux and macOS, an
  **Administrator** shell on Windows. The agent runs as root or SYSTEM in
  production, and several collectors read sources that require it
  (`/sys/class/dmi/id/product_uuid`, LUKS headers, `Get-BitLockerVolume`).
  Validating unprivileged proves the wrong thing and produces failures that
  look like defects.

  This is not theoretical: an unelevated Windows run of this exact procedure
  reported `encryption: permission_denied` because `Get-BitLockerVolume`
  answered "Access denied". That is the collector behaving correctly — it
  refuses to report "no encrypted volumes" when it could not look — but it will
  be filed as a bug by anyone who runs the procedure without elevation.
- A build for the target: `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o sentinelgo ./cmd/sentinelgo`
- **No backend needed.** Every command below is local and sends nothing over the
  network. They also never write `config.json` — the only paths that do are
  `-enable-auto-update` and the running agent's token refresh.

## 3. Procedure

Run all three, in order, on each platform.

### 3.1 Capability manifest — what the agent thinks it can do

```bash
sudo ./sentinelgo -capabilities
```

Check, for every key:

- `supported` only where the host really can provide the data.
- `not_present` where the hardware is genuinely absent (no TPM, no battery).
- `unsupported` where the tool is missing or the host will not expose it —
  **for example `network.routing_table` on a host without `ip`**.
- **Exactly one key should report `not_collected`: `peripherals.usb`.** No
  collector claims it in this build, so that is the honest answer. Any OTHER key
  reporting `not_collected` means a collector failed to register and is a
  finding.

- **`storage.smart` must NOT report `not_collected`.** It is claimed by the
  `physical_disks` collector as a sub-capability and describes the mechanism,
  not the result:
  - Linux: `supported` only when smartmontools is installed. **`unsupported` is
    the expected answer on a stock distribution** — smartctl is not installed by
    default, and that is precisely the actionable signal the state exists for.
  - macOS: `supported` (diskutil ships with the OS), but expect only
    `smart.healthy` to be populated — temperature, power-on hours and wear are
    always nil there, and Apple silicon internal NVMe often reports no SMART
    status at all.
  - Windows: always `supported`; Get-StorageReliabilityCounter is in-box.
- `unavailable_on_os` should be rare, and every occurrence should be
  investigable — it is a claim about the platform.

### 3.2 One full collection cycle

```bash
sudo ./sentinelgo -telemetry-cycle
```

This runs every collector and prints the sections. **Nothing is sent to the
backend** — but be precise about what it does do: a cycle also *enqueues* the
sections into the local outbound queue (`sentinelgo_telemetry_queue.db`), which
is why the output reports a "Queued" count. Those messages are only ever
transmitted if the agent later runs as a service with `telemetry_enabled: true`.
Clear them with `-telemetry-reset` if that matters.

For each section, confirm:

| Section | What a correct result looks like |
|---|---|
| `identity` | Real serial, model, machine ID. On Linux, `device_uuid` present (root-only read). On macOS, `asset_tag` and `board_serial` correctly **absent** — Apple firmware does not expose them |
| `virtualization` | `is_virtual` correct for the host; hypervisor named on a VM |
| `directory` | Linux: `domain_joined` only true on a realm-joined host. macOS: reflects `dsconfigad`. Never a guessed `false` |
| `sessions` | The logged-in user actually appears; `remote` true over SSH |
| `os` | `install_date` populated; `pending_reboot` correct (Linux: check with a pending kernel update) |
| `physical_disks` | Disks listed. SMART present only if `smartctl` is installed — otherwise the capability must say `unsupported`, not report healthy |
| `volumes` | Mount points and sizes match `df -h` / `diskutil list` |
| `network` | MTU matches `ip link` / `ifconfig`. DHCP state nil on a non-NetworkManager Linux host rather than a guessed value |
| `routes` | **Only present with `collect_routing_table: true`.** Compare against `ip route show` and `ip -6 route show` (Linux) or `netstat -rn` (macOS): same destinations, gateways and interfaces. Verify default routes render as `0.0.0.0/0` / `::/0`, on-link routes have an empty gateway, and macOS abbreviations (`192.168.1` → `192.168.1.0/24`) expand correctly |
| `encryption` | LUKS / FileVault state correct; `encryption_percentage` absent on Linux (LUKS has no partial state). **`permission_denied` here means the shell was not elevated, not a defect** |
| `patches` | Installed updates listed from dpkg/rpm history or `softwareupdate --history` |
| `security_posture` | Password policy and privileged accounts match `chage`/`pwpolicy` and the sudo/admin group |
| `persistence` | cron, systemd units and LaunchAgents/LaunchDaemons appear |
| `processes` | Process count roughly matches `ps aux | wc -l`. `cmdline` absent by default |
| `security_protection` | Firewall state matches `ufw status` / `firewall-cmd` / `socketfilterfw` |
| `secure_boot` | Matches `mokutil --sb-state` (Linux) / `csrutil status` and boot policy (macOS) |
| `tpm` | Present only where there is a TPM; Apple silicon reports the Secure Enclave honestly or not at all |
| `certificates` | Trust-store certificates listed with sane expiry dates |
| `health` | CPU/memory/disk percentages plausible; battery present on a laptop with real capacity and cycle count |
| `firmware`, `cpu`, `memory_modules` | Bridged from the legacy inventory. Compare against `dmidecode -t bios`, `lscpu`, `dmidecode -t memory` / `system_profiler SPHardwareDataType` |

Also check the run itself:

- No collector reports `error`, `timeout` or `permission_denied`. Any of the
  three is a finding — **provided the shell is elevated**. If it is not, expect
  `encryption: permission_denied` on Windows and several others on Unix, and
  re-run properly before recording anything.
- Total cycle duration. A Windows reference run took **~47 s** for 20 populated
  sections; the slowest collectors there were `network` (10.8 s), `patches`
  (9.4 s) and `encryption` (5.5 s). Anything dramatically beyond that on Linux
  or macOS is worth noting, particularly the `system_profiler` paths.
- `source` names the mechanism actually used — a fallback to a weaker source is
  visible here and would otherwise look like a normal success.
- Warnings are sanitised and contain no raw command output or hostnames.

### 3.3 Health and error surfacing

```bash
sudo ./sentinelgo -telemetry-health
sudo ./sentinelgo -telemetry-health -json
```

- Collectors that legitimately cannot run (no TPM, no battery) must **not**
  count as failures — `Status.Failed()` covers only `error`,
  `permission_denied` and `timeout`.
- Consecutive-failure counts should be zero on a healthy host.

### 3.4 Cancellation behaviour

```bash
# Start a cycle and interrupt it; no sentinelgo child processes may survive.
sudo ./sentinelgo -telemetry-cycle & sleep 2 && kill %1
sleep 5
ps -ef | grep -E 'smartctl|system_profiler|dsregcmd|ip route' | grep -v grep
```

The last command should print nothing. This checks the cancellation work in
`osinfo.CollectContext` and the context-aware security collector.

### 3.5 Reset between runs

```bash
sudo ./sentinelgo -telemetry-reset
```

Clears local telemetry section state only. **It does not touch the audit-log
queue, the software catalog, or credentials.**

## 4. Platform-specific things most likely to be wrong

Ranked by the likelihood that real output differs from what the parser tests
assume.

**Linux**

1. `ip route show` on a host with policy routing, multipath routes or a VPN —
   the parser skips `nexthop` continuation lines and `cache` entries; verify it
   does so on real output.
2. `loginctl list-sessions -o json` absent on non-systemd distributions.
3. `smartctl` not installed — the common case, and the capability must say so.
4. `nmcli` absent (systemd-networkd, ifupdown) — DHCP state must be nil, not
   `false`.
5. `/sys/class/dmi/id/product_uuid` unreadable when not root.

**macOS**

1. `system_profiler` is slow (1.5–4 s) — confirm the cycle stays inside its
   budget.
2. `diskutil list -plist` on APFS containers: volumes and physical disks must
   not be conflated.
3. `netstat -rn` abbreviated networks and `link#N` gateways — the two BSD-isms
   the parser handles.
4. TCC / Full Disk Access can silently empty a result rather than erroring.
5. Apple silicon exposes very little NVMe SMART data.

## 5. Windows reference run

For comparison, a real unprivileged Windows 11 run on 2026-08-21 with the
validation build produced:

- 20 of 22 sections populated; `encryption` denied (not elevated) and `tpm`
  reported `unsupported` on that host
- `routes` 61 entries, `processes` 472, `certificates` 38, `persistence` 23,
  `patches` 9
- Change detection seeded 11 baseline values and emitted **0 events**, which is
  correct: a first run must never turn a baseline into an event
- Chunking exercised on all five chunked sections (1 batch each at this size)

Use it as a shape check, not as a target — a Linux server will legitimately look
very different.

## 6. Recording results

Record outcomes in a **new** document (`08a-validation-results-<platform>.md`)
with the agent version, OS version, hardware, date, and the raw
`-telemetry-cycle` output. Do not edit this file to record results, and do not
mark any platform validated on the strength of a build succeeding.
