> ⚠️ **This document is stale and has not been verified against the current code.**
>
> This document claims tokens are encrypted at rest via `EncryptSensitiveData()`. **No such function exists** — `config.json` stores the access token, refresh token and agent secret in plaintext, protected only by filesystem ACLs. It also references `tenant_id` and `heartbeat_interval`, neither of which exists in the code.
>
> See [docs/telemetry/06-existing-code-observations.md](docs/telemetry/06-existing-code-observations.md) for the full list of documentation drift.

# SentinelGo — Process Flow & Architecture

> **DEPRECATED.** This document has been superseded by [`docs/08-project-overview.md`](docs/08-project-overview.md), the canonical architecture and runtime-flow reference. It is kept here for historical context only. Please refer to `docs/08` for accurate, current information.
>
> **Last updated:** 2026-05-10  
> **Version:** v2.1.5

---

## Table of Contents

1. [Overview](#overview)
2. [Service Lifecycle](#service-lifecycle)
3. [Execution Flow](#execution-flow)
4. [Task Dependency Graph](#task-dependency-graph)
5. [Authentication Flow](#authentication-flow)
6. [Audit Log Pipeline](#audit-log-pipeline)
7. [Heartbeat Flow](#heartbeat-flow)
8. [Auto-Update Flow](#auto-update-flow)
9. [Configuration](#configuration)
10. [Error Handling & Resilience](#error-handling--resilience)
11. [Cross-Platform Support](#cross-platform-support)
12. [File Structure](#file-structure)

---

## Overview

SentinelGo is a cross-platform agent that collects system information, sends heartbeats to a Supabase backend, syncs software inventory, and streams audit logs. It runs as a system service on Linux, Windows, and macOS.

---

## Service Lifecycle

```
┌─────────────────────────────────────────────────┐
│                  INSTALL                         │
│  sentinelgo -install                             │
│  ├─ Linux/Windows: kardianos/service.Install()   │
│  └─ macOS: launchctl load + plist                │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────┐
│              SERVICE START                       │
│  kardianos/service calls program.Start()         │
│  ├─ Load config.json                             │
│  ├─ Acquire process lock                         │
│  ├─ Create MainIntegration                       │
│  └─ MainIntegration.Start(ctx)                   │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────┐
│           MAIN INTEGRATION START                 │
│  1. Validate configuration                       │
│  2. Initialize Supabase auth service             │
│  3. InitSession from stored tokens               │
│  4. Preemptive token validation/refresh          │
│  5. Create & configure task scheduler            │
│  6. Start logging service (if audit logs on)     │
│  7. Start task scheduler                         │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────┐
│              RUNNING                             │
│  ├─ Scheduler runs initial tasks in order        │
│  ├─ Periodic tickers fire per configured interval │
│  ├─ Audit log collector streams in background    │
│  └─ Auto-update checker runs hourly              │
└──────────────────┬──────────────────────────────┘
                   │
                   ▼  (SIGINT / SIGTERM / service stop)
┌─────────────────────────────────────────────────┐
│              GRACEFUL SHUTDOWN                   │
│  program.Stop()                                  │
│  ├─ Cancel context                               │
│  ├─ Scheduler.Stop() (waits for running tasks)   │
│  ├─ LoggingIntegration.Stop() (flush + checkpoint)│
│  ├─ Release process lock                         │
│  └─ ─ ─ ─ ─ ─ ─ ─                               │
│  SERVICE STOPPED                                 │
└─────────────────────────────────────────────────┘
```

---

## Execution Flow

### Startup Sequence

```
main()
  │
  ├── Parse flags (-install, -uninstall, -run, etc.)
  │
  ├── (If -install)
  │     └─ Register as system service → exit
  │
  ├── (If -uninstall)
  │     └─ Remove service → exit
  │
  ├── (If -run or no flags → service mode)
  │
  │   program.Start(svc)
  │     ├─ Load config from config.json
  │     ├─ Acquire process lock (prevent duplicates)
  │     ├─ Create context with cancel
  │     └─ Go: mainIntegration.Start(ctx)
  │           │
  │           ├─ Step 1: cfg.ValidateConfiguration()
  │           ├─ Step 2: service.NewService(supabaseURL)
  │           ├─ Step 3: authSvc.InitSession(cfg)
  │           │         (sets JWT on Supabase client)
  │           ├─ Step 4: enhancedAuth.ValidateAndRefreshTokens()
  │           │         (preemptive refresh if near expiry)
  │           ├─ Step 5: Create default tasks + set intervals
  │           ├─ Step 6: Start logging integration (audit logs)
  │           └─ Step 7: scheduler.Start(cfg, authSvc)
  │                     ├─ Run initial tasks (dependency order)
  │                     └─ Start periodic tickers
```

### Shutdown Sequence

```
program.Stop(svc)
  │
  ├─ Cancel context (signals all goroutines)
  ├─ mainIntegration.Stop()
  │     ├─ scheduler.Stop()
  │     │     ├─ Set running=false
  │     │     ├─ Cancel context
  │     │     └─ Wait for all tasks (30s timeout)
  │     └─ loggingService.Stop()
  │           ├─ Cancel context
  │           ├─ Wait for goroutines
  │           ├─ Final flush of buffered logs
  │           └─ Save checkpoint
  └─ Release process lock
```

---

## Task Dependency Graph

```
auto-update (every 24h)
    │
    ▼ (must complete first)
agent-info-update (every 1h)
    │
    ▼ (must complete first)
software-sync (every 5min, configurable)
    │
    ▼ (must complete first)
audit-logs (every 5min, configurable)
```

**Execution order:** Tasks run sequentially in the order above. Each task waits for its dependencies to have completed at least once before it runs.

### Default Task Configuration

| Task | Interval | Depends On | Enabled |
|------|----------|------------|---------|
| `auto-update` | 24h | — | Always |
| `agent-info-update` | 1h | `auto-update` | Always |
| `agent-info-update` | Always |
| `software-sync` | 5min (configurable) | `heartbeat` | When `software_sync_enabled=true` |
| `audit-logs` | 5min (configurable) | `software-sync` | When `audit_logs_enabled=true` |

---

## Authentication Flow

### Token Initialization

```
1. Config loaded → cfg.AccessToken, cfg.RefreshToken
2. service.InitSession(cfg)
   └─ supabase.NewClient() with access token
3. Client ready for authenticated requests
```

### Preemptive Token Refresh

```
mainIntegration.Start()
  └─ enhancedAuth.ValidateAndRefreshTokens(ctx, cfg, refreshFunc)
        ├─ Check: is token close to expiry? (23h threshold)
        ├─ Yes → refreshWithRetry()
        │         ├─ Circuit breaker check
        │         └─ Exponential backoff: 1s → 2s → 4s
        └─ No → skip (token still valid)
```

### Reactive Token Refresh (on 401)

```
heartbeat.SendWithAuth()
  ├─ POST /rest/v1/rpc/agent_push_heartbeat
  ├─ Response: 401 Unauthorized
  └─ authSvc.RefreshToken(ctx, cfg)
        ├─ Serialized (only one refresh at a time)
        ├─ POST to Supabase auth endpoint
        ├─ Update cfg.AccessToken + cfg.RefreshToken
        ├─ cfg.SaveAtomic() (atomic write, 0600 perms)
        └─ Retry original request with new token
```

### Circuit Breaker

```
┌──────────────┐     ┌───────────┐     ┌──────────────┐
│  StateClosed  │────▶│ StateOpen  │────▶│StateHalfOpen │
│  (normal)     │     │ (5 fails)  │     │ (after 5min) │
│               │◀─────│            │     │              │
│               │reset │            │────▶│              │
└──────────────┘     └───────────┘     └──────────────┘
                           │
                           │ 5 consecutive auth failures
                           ▼
                   Disable for 5 minutes
```

- **maxFailures:** 5
- **resetTimeout:** 5 minutes
- **Effect:** When open, all auth attempts are blocked until timeout

---

## Audit Log Pipeline

```
┌─────────────┐    ┌──────────┐    ┌──────────┐    ┌───────────┐    ┌─────────┐
│  Collector  │───▶│  Parser  │───▶│  Buffer  │───▶│  Uploader │───▶│ Supabase│
│  (OS logs)  │    │(normalize)│   │ (in-mem) │    │ (batch +  │    │  RPC    │
└─────────────┘    └──────────┘    └──────────┘    │  retry)   │    └─────────┘
                                                    └───────────┘
         ▲                                              │
         │                                              ▼
    ┌─────────┐                                  ┌──────────┐
    │Real-time│                                  │ Checkpoint│
    │subscrip.│                                  │   Store   │
    └─────────┘                                  └──────────┘
```

### Collection Flow

1. **Collector** (`internal/auditlogs/collector/`) — OS-specific log gathering
   - Linux: systemd journal + file tailing (auth.log, syslog, etc.)
   - macOS: Unified Logging API
   - Windows: Event Log API
   - Produces `[]RawLogEntry`

2. **Parser** (`internal/auditlogs/parser/`) — Normalizes raw entries
   - Maps to `AuditLog` struct
   - Validates required fields
   - Truncates oversized event_data (max 10KB)

3. **Buffer** (`internal/logging/buffer.go`) — Thread-safe in-memory queue
   - Capacity: 50,000 entries
   - Deduplication via SHA256 hash (10,000 entry dedup set)
   - `Drain(0)` removes and returns ALL pending entries

4. **Uploader** (`internal/logging/uploader.go`) — Batched HTTP upload
   - Max 100 logs per batch
   - Up to 3 retries with exponential backoff (1s → 2s → 4s)
   - RPC endpoint: `/rest/v1/rpc/agent_insert_audit_logs_batch`
   - Payload wrapped in `{"payload": {...}}` envelope

5. **Checkpoint** (`internal/logging/checkpoint.go`) — Persists collection position
   - Atomic writes (write-tmp, then rename)
   - JSON file at `~/.sentinelgo/audit_checkpoint.json`

### Flush Behavior

```
Every flush_interval (default: 5min):
  ├─ Run collection cycle (collect new logs)
  ├─ Drain ALL buffered logs
  ├─ Upload via Uploader.Upload()
  │     ├─ Batch by category (system, security, network, mdm, other)
  │     ├─ Max 100 per HTTP request
  │     └─ Retry up to 3 times on failure
  └─ Save checkpoint on success
```

### RPC Payload Format

```json
{
  "payload": {
    "device_id": "abc123",
    "os_type": "linux",
    "agent_version": "v2.1.5",
    "source": "agent",
    "logs": [
      {
        "system": [
          {
            "event_type": "boot",
            "created_at": "2026-05-10T12:00:00Z",
            "severity": "info",
            "log_category": "SYSTEM_LOG",
            "source": "agent",
            "event_data": { "uptime": 60 }
          }
        ]
      },
      {
        "security": [
          {
            "event_type": "user_login",
            "created_at": "2026-05-10T12:01:00Z",
            "severity": "low",
            "log_category": "SECURITY_LOG",
            "source": "agent",
            "event_data": { "username": "admin", "method": "password" }
          }
        ]
      }
    ]
  }
}
```

---

## Auto-Update Flow

```
scheduler → handleAutoUpdate()
  │
  └─ updater.CheckAndApplyWithRetry(ctx, cfg)
        │
        ├─ Attempt 1:
        │     ├─ fetchLatestRelease() → GitHub API
        │     ├─ Compare cfg.CurrentVersion vs latest
        │     ├─ If newer: downloadAndVerify()
        │     │     ├─ Download binary
        │     │     ├─ Calculate SHA256 checksum
        │     │     └─ Verify against release checksums
        │     ├─ createBackup() → binary.backup
        │     ├─ Stop old processes
        │     ├─ atomicReplace() → rename new binary
        │     ├─ Update cfg.CurrentVersion (SaveAtomic)
        │     └─ restart() → spawn new process, exit
        │
        ├─ On failure → retry (up to 3 attempts)
        │     └─ Backoff: 1s → 2s
        │
        └─ On success → new process takes over
```

### Cross-Platform Restart

| Platform | Method |
|----------|--------|
| **Linux** | `os.Rename()` + `exec.Command(selfPath)` + `os.Exit(0)` |
| **macOS** | `launchctl stop/start` for managed restart |
| **Windows** | Batch script with timeout + move/rename |

---

## Configuration

### config.json Structure

```json
{
  "supabase_url": "https://your-project.supabase.co",
  "device_id": "auto-generated-uuid",
  "agent_id": "",
  "tenant_id": "",
  "access_token": "<jwt-access-token>",
  "refresh_token": "<jwt-refresh-token>",
  "current_version": "v2.1.5",
  "heartbeat_interval": "5m0s",
  "update_interval": "5m0s",
  "auto_update": false,
  "software_sync_enabled": true,
  "audit_logs_enabled": true,
  "log_flush_interval": "5m0s",
  "edge_function_url": "https://xxx.supabase.co/functions/v1/upsert-agent-software",
  "github_owner": "habib45",
  "github_repo": "SentinelGo"
}
```

### Token Storage Security
- File permissions: `0600` (owner read/write only)
- Atomic writes via `SaveAtomic()` (write temp → rename)
- Tokens encrypted at rest via `EncryptSensitiveData()`

---

## Error Handling & Resilience

| Component | Strategy |
|-----------|----------|
| **Token refresh** | Exponential backoff: 1s, 2s, 4s (max 3 attempts) |
| **Circuit breaker** | Opens after 5 failures; auto-resets after 5 minutes |
| **Heartbeat failure** | Non-fatal — logged, scheduler continues |
| **Log upload failure** | Retry 3x with backoff; logs stay in buffer |
| **Auto-update failure** | Retry 3x; rollback from backup on corruption |
| **Config corruption** | Atomic writes prevent partial state |
| **Process lock** | Prevents duplicate instances |
| **Graceful shutdown** | 30-second timeout for task completion |

---

## Cross-Platform Support

### Build Constraints

| File | Platform |
|------|----------|
| `collector_linux.go` | `linux && cgo` |
| `collector_darwin.go` | `darwin` |
| `collector_windows.go` | `windows` |
| `collector_stub.go` | All (fallback, no-op) |

### Service Management

| Platform | Package | Service Type |
|----------|---------|-------------|
| **Linux** | `kardianos/service` | systemd |
| **macOS** | `kardianos/service` + launchd plist | launchd |
| **Windows** | `kardianos/service` | Windows Service |

### Installation

```bash
# Linux
sudo ./sentinelgo -install
sudo systemctl enable --now sentinelgo

# macOS
sudo ./sentinelgo -install

# Windows (PowerShell, Admin)
.\sentinelgo.exe -install
```

---

## File Structure

```
SentinelGo/
├── cmd/sentinelgo/
│   └── main.go                    # Entry point, service lifecycle
├── internal/
│   ├── main_integration.go         # Orchestrates all components
│   ├── config/
│   │   └── config.go               # Config loading, validation, save
│   ├── auth/
│   │   ├── enhanced_auth.go        # Token refresh with circuit breaker
│   │   ├── circuit_breaker.go      # Circuit breaker pattern
│   │   └── auth_logger.go          # Structured auth event logging
│   ├── service/
│   │   ├── authService.go          # Supabase auth (token refresh)
│   │   ├── session_manager.go      # Session management (unused — dead code)
│   │   ├── agentService.go         # Agent info CRUD via PostgREST
│   │   ├── softwareService.go      # Software sync
│   │   └── auditLogService.go      # Audit log upload via RPC
│   ├── scheduler/
│   │   └── scheduler.go            # Task scheduling with dependencies
│   ├── heartbeat/
│   │   ├── heartbeat.go            # Heartbeat RPC calls
│   │   └── software.go             # Software info collection
│   ├── logging/
│   │   ├── logging.go              # Collection pipeline orchestration
│   │   ├── uploader.go             # Batched upload with retry
│   │   ├── buffer.go               # Thread-safe deduplicating buffer
│   │   ├── checkpoint.go           # Collection checkpoint persistence
│   │   └── stats.go                # Atomic statistics counters
│   ├── auditlogs/
│   │   ├── service.go              # Old audit service (legacy)
│   │   ├── parser.go               # Log normalization & validation
│   │   ├── interfaces.go           # Type definitions, interfaces
│   │   ├── collector/
│   │   │   ├── collector.go        # Collector interface
│   │   │   ├── collector_linux.go  # Linux (systemd journal + files)
│   │   │   ├── collector_darwin.go # macOS
│   │   │   ├── collector_windows.go# Windows
│   │   │   └── collector_stub.go   # Fallback (no-op)
│   │   ├── collector_linux.go      # Old Linux collector
│   │   ├── collector_darwin.go     # Old macOS collector
│   │   ├── collector_windows.go    # Old Windows collector
│   │   └── ErrInvalidInput.go      # Error type
│   ├── updater/
│   │   └── updater.go              # Auto-update with backup/rollback
│   ├── osinfo/
│   │   └── osinfo.go               # System info collection
│   └── constants/
│       └── supabase.go             # Supabase credentials (build-time)
├── migrations/
│   └── 001_create_audit_log_batch_rpc.sql  # RPC function DDL
├── tests/
│   ├── integration_test_fixed.go   # Integration tests (active)
│   ├── auth_test.go                # Auth tests
│   ├── heartbeat_rpc_test.go       # Heartbeat RPC tests
│   ├── audit_log_rpc_test.go       # Audit log RPC tests
│   ├── software_service_test.go    # Software service tests
│   └── ...                         # Additional test files
├── audit-config-sample.json        # Sample configuration
└── process_flow.md                 # This file
```

---

## Quick Start

```bash
# Build
go build ./cmd/sentinelgo/

# Configure (edit supabase_url, tokens, etc.)
nano audit-config-sample.json
cp audit-config-sample.json /etc/sentinelgo/config.json

# Install as service
sudo ./sentinelgo -config /etc/sentinelgo/config.json -install

# Verify
sudo systemctl status sentinelgo
sudo journalctl -u sentinelgo -f
```