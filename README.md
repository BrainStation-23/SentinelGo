<div align="center">

# SentinelGo

**One lightweight agent. Total endpoint visibility. Continuous compliance.**

A single, dependency-free binary that turns every Windows, macOS, and Linux device into a continuously-monitored, audit-ready endpoint — hardware inventory, security posture, encryption status, and tamper-evident audit logs, streamed to your backend in real time.

[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux-blue)](#runs-everywhere-your-fleet-does)
[![Build](https://img.shields.io/badge/build-CGO__free%20static%20binary-success)](#why-teams-choose-sentinelgo)
[![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8)](#build-from-source)
[![License](https://img.shields.io/badge/license-MIT-green)](#license)

</div>

---

## Why teams choose SentinelGo

Most compliance and asset-management tools ship a heavy stack: a kernel module here, a Python runtime there, a different installer per OS, and an agent that drifts out of date the moment you deploy it. SentinelGo takes the opposite approach.

- **Zero dependencies, anywhere.** Every build is a `CGO_ENABLED=0` static binary. No runtime, no shared libraries, no per-machine toolchain. Drop one file on a box and it runs — the same way on a 2019 Windows Server, an Apple Silicon MacBook, and an ARM64 Linux node.
- **Deploy once, stay current forever.** Built-in self-update checks GitHub Releases, downloads the right binary for the platform, and replaces itself with rollback protection — so your fleet never falls behind.
- **Runs as a first-class service.** Native Windows Service, systemd unit, and launchd daemon. Install with one command; it survives reboots and restarts on failure.
- **Built for compliance from the ground up.** Durable, at-least-once audit-log delivery backed by a local SQLite queue means events survive network outages and reboots instead of being silently dropped.
- **Tiny footprint.** A single background service designed for low CPU and memory — built to monitor, not to get in the way.

---

## What it captures

SentinelGo gives you a live, structured picture of every endpoint — far beyond "is it online."

### 🖥️ Complete hardware & system inventory
CPU (model, cores, clock, usage), memory, per-disk capacity and health, GPUs, RAM modules (per-slot), displays, audio devices, printers, and connected peripherals (with vendor/product IDs). Plus OS name and version, architecture, locale, timezone, uptime, and last boot — refreshed on every heartbeat.

### 🔐 Security & compliance posture
- **Disk encryption status** across all three platforms — BitLocker (Windows), FileVault (macOS), and LUKS (Linux), including hardware-vs-software encryption type.
- **Antivirus state** — installed products, whether they're enabled, and whether definitions are current.
- **Firewall** status and per-profile configuration.
- **OS hardening** — Secure Boot, VBS / HVCI memory integrity, Credential Guard (Windows), System Integrity Protection (macOS), SELinux / AppArmor / kernel lockdown (Linux).
- **Listening ports** mapped to the owning process.
- **Firmware** — BIOS/UEFI vendor and version, TPM presence and version.

### 🌐 Network visibility
Per-adapter details: MAC, type, link speed, connection status, IPv4/IPv6 addressing (with DHCP and subnet info), default gateway, DNS servers, and Wi-Fi SSID + signal strength.

### 📦 Software & extension inventory
Installed applications and versions across every major source — Windows programs and Microsoft Store, Debian/RPM/Snap/Flatpak, Homebrew and casks, and the macOS App Store — with first-seen / last-seen change tracking. Includes browser-extension inventory for Chrome, Firefox, Edge, and Brave.

### 📝 Tamper-evident audit log streaming
Continuous, normalized audit events from each platform's native source — Windows Event Log (Security, System, Defender, PowerShell, Task Scheduler, Firewall, RDP, Group Policy, and more), Linux auth/syslog and journald, and the macOS unified log. Events are categorized, severity-tagged, checkpointed, and uploaded in batches with exponential-backoff retry, so nothing is lost across restarts or outages.

### 👥 Local account inventory
Local user accounts with group membership — without collecting sensitive credential material.

---

## Runs everywhere your fleet does

| Platform | Architectures | Service model |
|---|---|---|
| **Windows** | amd64 | Windows Service |
| **macOS** | Apple Silicon (arm64) & Intel (amd64) | launchd daemon |
| **Linux** | amd64, arm64 | systemd unit |

Every target is cross-compiled from a single host into a static binary — no per-platform build farm required.

---

## How it works

```
  ┌─────────────┐     authenticate (JWT)     ┌──────────────────┐
  │  SentinelGo  │ ─────────────────────────▶ │                  │
  │    agent     │ ◀───── tasks / config ──── │  Your Supabase   │
  │              │                            │     backend      │
  │  • metrics   │ ───── heartbeat ─────────▶ │                  │
  │  • software  │ ───── inventory ─────────▶ │  • dashboards    │
  │  • auditlog  │ ───── log batches ───────▶ │  • alerting      │
  └─────────────┘                            └──────────────────┘
         │
         └──── daily ──▶ GitHub Releases ──▶ self-update + restart
```

1. **Authenticate** — the agent logs in to a Supabase edge function and receives a short-lived JWT, auto-refreshed in the background.
2. **Report** — it collects system metrics and sends a heartbeat on a configurable interval (default 5 minutes), plus periodic full hardware/software inventory.
3. **Stream** — audit logs are collected, normalized, queued durably, and uploaded with at-least-once delivery.
4. **Stay current** — a daily release check downloads, verifies, and applies updates, then restarts cleanly.

---

## Quick start

1. Download the release for your OS/arch from [GitHub Releases](https://github.com/BrainStation-23/SentinelGo/releases/latest).
2. Place it in the install location (`/opt/sentinelgo/` on Linux/macOS, `C:\sentinelgo\` on Windows).
3. Add a `config.json` next to the binary (see [Configuration](#configuration)).
4. Register the service:

   ```bash
   ./sentinelgo -install     # admin/root — installs and starts the service
   ./sentinelgo -run         # or run in the foreground for debugging
   ```

Full per-OS steps: [`installation-doc/INSTALLATION.md`](installation-doc/INSTALLATION.md).

---

## Configuration

The agent reads a single JSON file. Default locations:

- Linux / macOS: `/opt/sentinelgo/.sentinelgo/config.json`
- Windows: `C:\sentinelgo\.sentinelgo\config.json`

Override the path with `-config <path>`. Common fields:

```json
{
  "supabase_url": "https://<your-project>.supabase.co",
  "supabase_key": "<anon-key>",
  "agent_secret": "<agent-login-secret>",
  "auto_update": true,
  "auto_update_interval": "24h",
  "update_interval": "5m",
  "audit_logs_enabled": true,
  "software_sync_enabled": true,
  "log_flush_interval": "5m"
}
```

Every field can also be set via environment variable. The agent never embeds credentials in the binary — it authenticates at runtime and rotates its JWT automatically. Full reference: [`docs/02-config-module.md`](docs/02-config-module.md).

---

## Command-line interface

```bash
sentinelgo -install            # install as a system service (admin/root)
sentinelgo -uninstall          # remove the service
sentinelgo -run                # run in the foreground
sentinelgo -status             # show installed/running processes and versions
sentinelgo -version            # print version
sentinelgo -config PATH        # use a custom config file

sentinelgo -collect-logs       # force an immediate audit-log collection
sentinelgo -upload-logs        # flush pending audit logs
sentinelgo -software-list      # show installed software inventory
sentinelgo -agent-info-update  # refresh hardware/system inventory
```

Full flag reference: [`docs/agent-commands-guide.md`](docs/agent-commands-guide.md).

---

## Build from source

```bash
make build                # dev build -> bin/sentinelgo[.exe]
make test                 # go test ./...
make verify-cross         # type-check every GOOS/GOARCH with CGO_ENABLED=0
make check-no-cgo         # fail if any `import "C"` is reintroduced
make pre-release          # quality gate + build
make release VERSION=vX.Y.Z
```

All builds are `CGO_ENABLED=0` static binaries cross-compiled from a single host. Go 1.25+ required.

---

## Documentation

| Document | Covers |
|---|---|
| [`docs/08-project-overview.md`](docs/08-project-overview.md) | Architecture, package layout, runtime flow |
| [`docs/01-main-module.md`](docs/01-main-module.md) | CLI, flag parsing, service entry point |
| [`docs/02-config-module.md`](docs/02-config-module.md) | Configuration schema and validation |
| [`docs/05-osinfo-module.md`](docs/05-osinfo-module.md) | Cross-platform hardware metrics |
| [`docs/06-service-module.md`](docs/06-service-module.md) | Service lifecycle and auth |
| [`docs/07-updater-module.md`](docs/07-updater-module.md) | Self-update flow |
| [`docs/audit-logs-architecture.md`](docs/audit-logs-architecture.md) | Audit-log pipeline |
| [`installation-doc/INSTALLATION.md`](installation-doc/INSTALLATION.md) | Per-OS install steps |

---

## Security & privacy

- All backend communication is over HTTPS with a per-agent JWT, obtained at runtime and rotated.
- Local-account collection captures usernames and group membership only — never credential material.
- Backend access is gated by Supabase Row Level Security.

---

## License

MIT
