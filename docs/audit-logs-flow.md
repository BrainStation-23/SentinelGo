# Audit Logs System

## Overview

The SentinelGo audit logs system collects, processes, and uploads system logs to Supabase. It provides a robust pipeline for monitoring system events across different operating systems.

## Architecture

```
OS Logs → Collector → Parser → SQLite Store → Uploader → Supabase
```

### Components

1. **Collector** - OS-specific log collection (Linux, Windows, macOS)
2. **Parser** - Normalizes raw log entries into structured format
3. **Store** - SQLite queue for pending logs with deduplication
4. **Uploader** - Batches and uploads logs to Supabase with retry logic
5. **Checkpoint** - Tracks last read position to prevent duplicates

---

## Entry Points

### 1. Standalone Mode (`-audit-logs` flag)

**Command:**
```bash
sudo ./sentinelgo -audit-logs -config audit-config-sample.json
```

**Behavior:**
- Sends simple heartbeat every 30 seconds
- Only sends "system_check" event to Supabase
- Does NOT collect actual system logs
- Useful for basic connectivity testing

**Implementation:** `cmd/sentinelgo/commands.go` → `handleAuditLogsStandalone()`

### 2. Main Integration Mode (`-run` flag)

**Command:**
```bash
sudo ./sentinelgo -run -config audit-config-sample.json
```

**Behavior:**
- Full audit log collection pipeline
- Runs automatically when `audit_logs_enabled: true` in config
- Collects actual system logs from multiple sources
- Processes and uploads logs periodically

**Implementation:** `internal/main_integration.go` → `Start()`

---

## Main Integration Pipeline

### Initialization

**File:** `internal/logging/logging.go` → `NewLoggingIntegration()`

```go
NewLoggingIntegration(cfg)
├── checkpointDir = filepath.Dir(cfg.Path)  // /tmp/sentinelgo or config dir
├── CheckpointStore = NewCheckpointStore(checkpointDir)
├── Store = auditlogstore.Open(auditlogs.sqlite)
├── Collector = collector.NewCollector()  // OS-specific
├── Parser = parser.NewParser()
└── Uploader = NewUploader(cfg)
```

**Database Location:**
- Default: `/tmp/sentinelgo/auditlogs.sqlite`
- Config-based: Same directory as config file

### Startup

**File:** `internal/logging/logging.go` → `Start()`

```go
Start(ctx)
├── Load checkpoints from disk
├── Start collectionLoop goroutine (periodic collection)
└── Start subscriptionLoop goroutine (real-time streaming)
```

### Collection Loop

Runs every `log_flush_interval` (default: 5 minutes)

**File:** `internal/logging/logging.go` → `collectionLoop()`

```
On ticker:
├── runCollection(ctx)
│   ├── collectionTime = now
│   ├── windowStart = now - flushInterval
│   ├── Collect raw logs from OS (since checkpoint)
│   ├── Filter: Timestamp >= windowStart
│   ├── Parse raw entries → AuditLog models
│   ├── Insert into SQLite store (dedup by hash)
│   └── Update checkpoint to latest position
│
└── uploader.UploadFromStore(ctx, store)
    ├── Get pending logs from SQLite (chunk size: 500)
    ├── Upload batches to Supabase (max 100 per batch)
    ├── Delete successfully uploaded logs
    └── Save checkpoint on success
```

---

## Component Details

### 1. Collector

**Interface:** `internal/auditlogs/collector/collector.go`

```go
type Collector interface {
    Collect(ctx context.Context, checkpoint CheckpointData) ([]RawLogEntry, CheckpointData, error)
    Subscribe(ctx context.Context, ch chan<- RawLogEntry) error
    Sources() []string
}
```

**OS-Specific Implementations:**

#### Linux (`collector_linux.go`)
- **Sources:** journal, auth.log, syslog, kern.log
- **Methods:** Uses `journalctl` and file watching
- **Real-time:** Supports journal subscription

#### Windows (`collector_windows.go`)
- **Sources:** Windows Event Log (Security, System, Application)
- **Methods:** Uses Windows Event Log API
- **Real-time:** Supports event log subscription

#### macOS (`collector_darwin.go`)
- **Sources:** system.log, asl (Apple System Log)
- **Methods:** Uses log command and ASL API
- **Real-time:** Supports log streaming

**RawLogEntry Structure:**
```go
type RawLogEntry struct {
    Timestamp  time.Time
    Source     string  // e.g. "windows_security", "journal", "auth.log"
    EventID    string  // OS-specific event ID
    RawMessage string
    Severity   string
    Metadata   map[string]string
}
```

### 2. Parser

**File:** `internal/auditlogs/parser/`

**Purpose:** Converts `RawLogEntry` → `models.AuditLog`

**Normalization:**
- Event types (login, logout, privilege escalation, etc.)
- Log categories (security, system, network, MDM)
- Severity levels (critical, high, medium, low, info)
- Structured event data extraction

### 3. Store (SQLite)

**File:** `internal/auditlogstore/store.go`

**Database:** `auditlogs.sqlite`

**Schema:**
```sql
CREATE TABLE IF NOT EXISTS audit_log_queue (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    log_hash      TEXT    NOT NULL,
    device_id     TEXT    NOT NULL,
    os_type       TEXT    NOT NULL,
    agent_version TEXT    NOT NULL,
    event_type    TEXT    NOT NULL,
    log_category  TEXT    NOT NULL,
    source        TEXT    NOT NULL,
    severity      TEXT    NOT NULL,
    timestamp     TEXT    NOT NULL,
    event_data    TEXT    NOT NULL,
    stored_at     DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX idx_audit_log_hash ON audit_log_queue(log_hash);
CREATE INDEX idx_audit_log_stored ON audit_log_queue(stored_at);
```

**Methods:**
- `Insert(logs)` - Inserts logs with deduplication by `log_hash`
- `GetPending(limit)` - Retrieves logs for upload (oldest first)
- `DeleteByIDs(ids)` - Removes successfully uploaded logs

**Deduplication:**
- Uses SHA-256 hash of log content
- `INSERT OR IGNORE` prevents duplicates
- Index on `log_hash` for fast lookup

### 4. Uploader

**File:** `internal/logging/uploader.go`

**Configuration:**
- Batch size: 100 logs per batch
- Chunk size: 500 logs per cycle from store
- Max retries: 3
- Backoff: Exponential (1s, 2s, 4s)

**Upload Flow:**
```
GetPending(500) from SQLite
├── Split into batches of 100
├── For each batch:
│   ├── Build payload
│   ├── Send to Supabase RPC
│   ├── Retry on failure (max 3)
│   └── Track success/failure
├── Delete successful batches from SQLite
└── Save checkpoint
```

**Endpoint:** `agent_insert_audit_logs_batch` RPC

**Headers:**
```
Content-Type: application/json
Authorization: Bearer <access_token>
X-Device-ID: <device_id>
apikey: <supabase_anon_key>
```

### 5. Checkpoint Store

**File:** `internal/logging/checkpoint.go`

**Location:** `checkpoints.json` in config directory

**Purpose:** Track last read position per source

**Structure:**
```json
{
  "journal": {"cursor": "s=..."},
  "auth.log": {"offset": 12345},
  "syslog": {"offset": 67890}
}
```

**Benefits:**
- Prevents duplicate log collection
- Resumes from last position after restart
- Source-specific tracking

---

## Configuration

**File:** `audit-config-sample.json`

```json
{
  "audit_logs_enabled": true,
  "log_flush_interval": "5m0s",
  "log_storage_enabled": true,
  "device_id": "...",
  "supabase_url": "https://...",
  "access_token": "...",
  "refresh_token": "..."
}
```

**Settings:**

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `audit_logs_enabled` | bool | true | Enable/disable audit logs service |
| `log_flush_interval` | duration | 5m0s | Collection/upload interval |
| `log_storage_enabled` | bool | true | Enable local SQLite storage |
| `device_id` | string | - | Unique device identifier |
| `supabase_url` | string | - | Supabase project URL |

---

## Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     OS Log Sources                           │
│  (journal, auth.log, syslog, kern.log, Event Log)           │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                      Collector                               │
│  - OS-specific implementation                               │
│  - Collects logs since checkpoint                            │
│  - Returns RawLogEntry[]                                     │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                       Parser                                 │
│  - Normalizes event types                                    │
│  - Categorizes logs (security, system, network)             │
│  - Extracts structured data                                  │
│  - Returns AuditLog[]                                        │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    SQLite Store                              │
│  - auditlogs.sqlite                                         │
│  - Deduplicates by hash                                      │
│  - Queues for upload                                        │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                      Uploader                                │
│  - Batches logs (100 per batch)                             │
│  - Uploads to Supabase RPC                                  │
│  - Retries on failure (3x)                                  │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                      Supabase                                │
│  - agent_insert_audit_logs_batch RPC                         │
│  - Stores logs in database                                  │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
                    Delete from SQLite
                           │
                           ▼
                    Save Checkpoint
```

---

## Log Categories

### Security
- Login/logout events
- Privilege escalation
- Authentication failures
- Sudo usage
- SSH sessions

### System
- Service starts/stops
- System boot/shutdown
- Package installations
- Configuration changes

### Network
- Connection attempts
- Firewall changes
- DNS queries
- Network interface changes

### MDM (Mobile Device Management)
- Device enrollment
- Policy applications
- Compliance status
- Remote commands

---

## Event Types

| Event Type | Description | Example Sources |
|------------|-------------|-----------------|
| `login` | User login | auth.log, Event Log |
| `logout` | User logout | auth.log, Event Log |
| `privilege_escalation` | Sudo, admin access | auth.log, Event Log |
| `service_start` | Service started | journal, Event Log |
| `service_stop` | Service stopped | journal, Event Log |
| `package_install` | Software installed | journal, dpkg/rpm logs |
| `network_connection` | Network activity | kern.log, firewall logs |
| `firewall_change` | Firewall rules modified | kern.log, iptables |

---

## Error Handling

### Collection Errors
- Logged with `[logging] collection cycle error`
- Does not stop the service
- Retries on next cycle

### Upload Errors
- Logged with `[logging] upload error`
- Failed logs remain in SQLite
- Retried on next cycle
- Max 3 retries per batch with exponential backoff

### Database Errors
- Logged with specific error message
- May require manual intervention
- Check file permissions and disk space

---

## Monitoring

### Statistics

**File:** `internal/logging/logging.go` → `GetStatistics()`

```go
type LoggingStats struct {
    Collected int64  // Total logs collected
    Uploaded  int64  // Total logs uploaded
    Errors    int64  // Total errors encountered
}
```

### Check Queue Size

```bash
sudo -u sentinelgo sqlite3 /tmp/sentinelgo/auditlogs.sqlite "SELECT COUNT(*) FROM audit_log_queue;"
```

### View Pending Logs

```bash
sudo -u sentinelgo sqlite3 /tmp/sentinelgo/auditlogs.sqlite "SELECT * FROM audit_log_queue LIMIT 10;"
```

### Check Upload Status

Logs show:
```
[uploader] uploaded and removed 100 logs from store
[logging] checkpoint save error: ...
```

---

## Troubleshooting

### Issue: "unable to open database file (14)"

**Cause:** File permission issues

**Solution:**
```bash
sudo chown -R sentinelgo:sentinelgo /tmp/sentinelgo
sudo chown -R sentinelgo:sentinelgo /opt/sentinelgo/.sentinelgo
```

### Issue: Logs not collecting

**Check:**
1. `audit_logs_enabled: true` in config
2. Service is running: `sudo ./sentinelgo -status`
3. Check logs for errors
4. Verify log sources exist on system

### Issue: Logs not uploading

**Check:**
1. Network connectivity
2. Supabase URL and credentials
3. Access token not expired
4. Check upload error logs

### Issue: Duplicate logs

**Cause:** Checkpoint not saved

**Solution:**
- Check checkpoint file permissions
- Verify checkpoint directory is writable
- Manual checkpoint reset if needed

---

## Performance Considerations

### Memory Usage
- Collector: Batches logs to limit memory
- Store: Uses SQLite with WAL mode
- Uploader: Processes in chunks of 500

### Disk Usage
- SQLite grows with pending logs
- Logs deleted after successful upload
- Checkpoint file is small (< 1KB)

### Network Usage
- Batch size: 100 logs per request
- Compression: JSON payload
- Retry logic handles transient failures

---

## Security Considerations

### Credential Storage
- Access tokens in config file
- Use environment variables for production
- Rotate tokens regularly

### Data in Transit
- HTTPS required for Supabase
- TLS certificate validation
- No plaintext credentials in logs

### Data at Rest
- SQLite file permissions
- Encrypt at rest if needed
- Regular cleanup of old logs

---

## Development

### Adding New Log Sources

1. Implement `Collector` interface for OS
2. Add source to `Sources()` method
3. Update parser for new format
4. Test with sample logs

### Testing

**Unit Tests:** `tests/audit_log_test.go`

**Integration Tests:** `tests/integration_test.go`

**Run Tests:**
```bash
go test ./tests/...
```

---

## File Reference

| File | Purpose |
|------|---------|
| `internal/logging/logging.go` | Main orchestration |
| `internal/auditlogs/collector/collector.go` | Collector interface |
| `internal/auditlogs/collector/collector_linux.go` | Linux implementation |
| `internal/auditlogs/collector/collector_windows.go` | Windows implementation |
| `internal/auditlogs/collector/collector_darwin.go` | macOS implementation |
| `internal/auditlogs/parser/` | Log parsing logic |
| `internal/auditlogstore/store.go` | SQLite queue |
| `internal/logging/uploader.go` | Supabase upload |
| `internal/logging/checkpoint.go` | Checkpoint management |
| `internal/service/auditLogService.go` | RPC client |
| `internal/main_integration.go` | Integration startup |
| `cmd/sentinelgo/commands.go` | CLI commands |

---

## Version History

- **v2.1.10** - Initial audit logs implementation
- **v2.1.13** - Added real-time subscription support
- **v2.1.14** - Improved error handling and retry logic
