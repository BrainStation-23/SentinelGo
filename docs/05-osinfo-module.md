# SentinelGo — OSInfo Module (`internal/osinfo`)

Single-call hardware inventory. The entry point is
`osinfo.Collect()` and it returns a fully populated
`shared.SystemInfo` snapshot. There is no streaming and no caching —
every call re-reads everything from the host.

> **See also:** the consumer that actually uploads the result,
> [`internal/service/agent`](../internal/service/agent), which calls
> `osinfo.Collect()` on the `agent_info_update_interval` cadence
> (default 1h — see [`docs/02`](02-config-module.md)). The
> upload path is described in
> [`docs/08-project-overview.md`](08-project-overview.md).

## Public surface

| Symbol                 | Returns              | Purpose                                                                 |
| ---------------------- | -------------------- | ----------------------------------------------------------------------- |
| `osinfo.Collect()`     | `*shared.SystemInfo` | One-shot snapshot of all 30+ hardware / OS fields.                     |
| `shared.SystemInfo`    | struct (JSON tagged) | The unified payload posted to the `agent-info` Edge Function.           |
| `shared.CPUInfoDetailed`, `shared.RAMInfo`, `shared.DiskDevice`, `shared.GPU`, `shared.Display`, `shared.AudioDevice`, `shared.Printer`, `shared.PeripheralDevice`, `shared.NetAdapter`, `shared.OSInformation`, `shared.UserWithGroup`, `shared.SecurityInfo` | structs | Granular sub-types — see `internal/osinfo/shared/types.go`. |

`Collect()` returns `nil` if `host.Info()` itself fails (very rare —
no platform fallback). Sub-package failures are logged and the
corresponding field is left as its zero value.

## Package layout

```
internal/osinfo/
  collect.go              # Collect() — top-level entry point
  shared/
    types.go              # SystemInfo + all sub-types, with json tags
    format.go             # byte/percent formatters
    helpers.go            # tiny shared utils (string trimming, etc.)
  cpu/                    # physical + logical cores, model, current load
  ram/                    # stick count, size, speed, manufacturer
  disk/                   # per-device smart summary (used by RAM section too)
  gpu/                    # discrete + integrated GPUs
  display/                # connected monitors, resolution, refresh rate
  audio/                  # input / output devices
  printers/               # installed printers + default
  peripherals/            # keyboards, mice, webcams, etc. (USB / Bluetooth)
  network/                # adapters, IPv4/IPv6, primary MAC
  system/                 # firmware, OS info, kernel, FQDN, TPM, chassis
  users/                  # local accounts with primary group
  security/               # SecurityInfo sub-type (disk encryption, AV, firewall)
```

Each sub-package exposes one `Get()` (or `Collect()` for `security/`)
that returns the sub-type or `nil`/`[]T{}` on error. The sub-packages
are where the cross-platform split lives — Windows uses `wmic` /
PowerShell / `sysinfo`; macOS uses `ioreg` / `system_profiler`;
Linux reads `/proc`, `/sys`, and `dmidecode` where present.

## What `Collect()` actually reads

A single call touches, roughly in this order:

1. **gopsutil** (`host.Info`, `mem.VirtualMemory`, `disk.Usage("/")`,
   `net.IOCounters`, `net.Interfaces`) for the headline fields:
   hostname, uptime, OS edition, kernel, memory, root disk, network
   counters, MAC addresses.
2. **CPU** (`cpu.Get`) — model name, physical + logical cores, current
   usage percent, plus the detailed per-CPU breakdown
   (`CPUInfoDetailed`).
3. **RAM** (`ram.Get`) — DIMM count, per-stick size and speed.
4. **Disks** (`disk.Get`) — every block device, model, size.
5. **GPUs**, **displays**, **audio devices**, **printers**,
   **peripherals** — each a one-shot read of OS inventory APIs.
6. **Network adapters** (`network.Get`) — the rich per-adapter
   struct (IPv4 + IPv6 addresses, gateway, DNS, link speed).
7. **System metadata** (`system.Get*`) — firmware type / vendor /
   version, serial, hardware model, OSQuery version, battery
   condition, FQDN, chassis type, kernel, TPM version.
8. **Local users** (`users.Get`) — usernames + primary group.
9. **Security** (`security.Collect`) — disk encryption status,
   anti-virus product, firewall state, packed into a `SecurityInfo`.
10. **Agent version** — read from the in-memory `config.Config`
    loaded by `config.Load("")` at the top of `Collect()`. On
    startup failure the field is left as `""` and the upload is
    skipped by the caller.

The whole call typically takes 200-600 ms on a modern host, dominated
by `osquery` / `system_profiler` / `wmic` invocations. It is run on
the `agent_info_update_interval` (default 1h), not on every
heartbeat, to keep the per-tick overhead bounded.

## Where the result goes

`osinfo.Collect()` does **not** upload anything. The result is
serialized to JSON by `internal/service/agent` (the periodic
agent-info service in the kardianos service tree) and POSTed to the
`agent-info` Edge Function with the agent's JWT. The Edge Function
is the one that maps each `SystemInfo` field to the corresponding
`agent_hardware` row in Supabase.

This means the agent-info upload is **independent of the heartbeat
upload** — they have separate intervals, separate endpoints, and
separate failure handling. See [`docs/06-service-module.md`](06-service-module.md)
for the auth and the Edge Function contract.

## What this module is not

- Not a real-time monitor. A single `Collect()` is a point-in-time
  snapshot. Continuous metrics (CPU usage over time, etc.) are out
  of scope here — heartbeat is the place for those, when it ships.
- Not a threat-detection module. The `security/` sub-package only
  reports disk encryption / AV / firewall status.
- Not OSQuery itself. `OSQueryVersion` is a string field reported by
  the host; the agent does not shell out to `osqueryi`.
