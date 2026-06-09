# SentinelGo Audit Log Collection System

## Overview

The SentinelGo Audit Log Collection System is a production-grade, cross-platform MDM agent module designed to collect, normalize, and transmit audit logs from Windows, Linux, and macOS systems to a remote MDM backend.

## Architecture

The system follows Clean Architecture principles with strict separation of concerns:

```
cmd/sentinelgo/main.go             - CLI entry point; -audit-logs flag runs the audit-logs subsystem
internal/main_integration.go       - Wires the audit-logs subsystem into the main service loop
internal/auditlogs/
  collector/
    collector.go                   - Collector interface and shared types
    collector_windows.go           - Windows Event Log collection
    collector_linux.go             - Linux journald / syslog collection
    collector_darwin.go            - macOS unified-log collection
    collector_parse.go             - Channel-specific record parsing
    collector_exec.go              - Privilege-aware exec helper (sudo, runas)
    collector_stub.go              - No-op collector for unsupported builds
  parser/
    parser.go                      - Log normalization and severity mapping
internal/auditlogstore/            - SQLite-backed durable queue for audit events
internal/logging/uploader.go       - HTTPS batch uploader to the Supabase Edge Function
```

## Core Components

### 1. Interfaces (interfaces.go)

**LogCollector Interface**
- `Start(ctx context.Context) error` - Begin collection process
- `Stop() error` - Graceful shutdown
- `CollectBatch(ctx, checkpoint) ([]RawLog, Checkpoint, error)` - Batch collection
- `SubscribeToRealTime(ctx, callback)` - Real-time streaming
- `GetSupportedCategories() []string` - Supported log categories
- `GetCheckpoint() (Checkpoint, error)` - Current checkpoint state

**LogParser Interface**
- `ParseRawLog(raw RawLog) (AuditLog, error)` - Parse raw to structured
- `ValidateLog(log AuditLog) error` - Validate log format
- `NormalizeEvent(rawEvent interface{}) (string, error)` - Normalize event data

**LogTransmitter Interface**
- `TransmitBatch(ctx, batch) error` - Send batch to backend
- `TransmitSingle(ctx, log) error` - Send single critical event
- `GetBatchSize() int` - Optimal batch size
- `IsHealthy(ctx) error` - Health check endpoint

### 2. OS-Specific Collectors

#### Windows (collector_windows.go)
**Native API Implementation:**
- Uses Windows Event Log API (EvtQuery, EvtSubscribe, EvtNext, EvtRender)
- No CLI tools or PowerShell dependencies
- Handles UTF-16 conversions and proper resource management
- Supports real-time subscription and batch queries

**Event Channels:**
- Security (4624, 4625, 4672 - authentication events)
- System (6005, 6006, 6008, 41 - system lifecycle)
- Application
- Windows Defender Operational
- PowerShell Operational

**Checkpointing:** Event Record ID for exact positioning

#### Linux (collector_linux.go)
**Primary Implementation:**
- File-based log collection with fallback to journalctl
- Monitors standard log files: /var/log/syslog, /var/log/auth.log, etc.
- Handles log rotation detection and offset tracking

**Fallback journalctl Support:**
- `journalctl --since timestamp --output=json`
- Cursor-based checkpointing when systemd journal available
- Structured field extraction

**Checkpointing:** File offset + journal cursor

#### macOS (collector_darwin.go)
**Implementation:**
- File-based collection using `log show` command
- Real-time streaming with `log stream --style=json`
- Crash report monitoring from standard directories

**Log Sources:**
- /var/log/system.log
- /var/log/install.log  
- /var/log/appfirewall.log
- Crash reports from ~/Library/Logs/DiagnosticReports

**Checkpointing:** Timestamp-based positioning

### 3. Log Parser (parser.go)

**Normalization Features:**
- Event type mapping (boot, shutdown, login, security, etc.)
- Severity classification (critical, high, medium, low, info)
- Category assignment (SYSTEM_LOG, SECURITY_LOG, AGENT_LOG, etc.)
- JSON event data normalization with schema compliance

**Event-Specific Normalization:**
- Boot events: boot_type, boot_duration
- Security events: threat_level, action_taken
- Authentication events: username, auth_method, auth_result
- Upgrade events: previous_version, new_version

**Validation:**
- Required field validation
- Timestamp format validation (RFC3339)
- Category and severity validation
- JSON structure validation

### 4. Service Layer (service.go)

**AuditLogService Features:**
- Configurable batch processing (default 100 logs/batch)
- Automatic retry with exponential backoff
- Graceful shutdown with buffer flush
- Real-time and scheduled collection modes
- Checkpoint management for durability

**HTTP Transmitter:**
- HTTPS transmission to Supabase Edge Functions
- JWT authentication with access tokens
- Configurable retry logic (3 attempts, 5s delay)
- Health check endpoint monitoring

**File Checkpoint Manager:**
- JSON-based checkpoint persistence
- Atomic file operations
- Recovery from corruption

## Data Model

### AuditLog Structure
```json
{
  "created_at": "2026-04-12T12:30:15.456Z",
  "agent_id": "ca33f7b4-05e4-4af7-89fc-73e55c4a8de6",
  "device_id": "dev-001", 
  "log_category": "SYSTEM_LOG",
  "event_type": "boot",
  "os_type": "linux",
  "agent_version": "2.1.3",
  "severity": "low",
  "source": "agent",
  "event_data": "{\"os_version_before\": \"20.03\", \"os_version_after\": \"20.04\"}"
}
```

### Batch Transmission Format
```json
{
  "agent_id": "ca33f7b4-05e4-4af7-89fc-73e55c4a8de6",
  "device_id": "dev-001",
  "os_type": "linux",
  "agent_version": "2.1.3",
  "source": "agent",
  "logs": [
    {
      "system": [
        {
          "event_type": "boot",
          "created_at": "2026-04-12T12:30:15.456Z",
          "severity": "low", 
          "log_category": "SYSTEM_LOG",
          "event_data": {...}
        }
      ]
    }
  ]
}
```

## Configuration

### Service Configuration
```json
{
  "audit_logs": {
    "enabled": true,
    "max_batch_size": 100,
    "collection_interval": "30s", 
    "flush_interval": "1m0s",
    "real_time_enabled": true,
    "retry_attempts": 3,
    "retry_delay": "5s",
    "api_endpoint": "https://<your-project>.supabase.co/functions/v1/batch-logs"
  }
}
```

### OS-Specific Settings
- **Windows:** Event channels and specific Event IDs
- **Linux:** File paths and journalctl arguments  
- **macOS:** Log file paths and crash report directories

## Security

### Transmission Security
- HTTPS (TLS 1.2+) required for all API communication
- JWT authentication with access tokens
- No sensitive data in logs or configuration
- Optional log integrity hashing

### Local Security
- Checkpoint files stored in user home directory
- No plaintext credentials in configuration files
- Proper file permissions (0600) for sensitive data

## Performance

### Resource Management
- Configurable batch sizes to balance memory vs. network efficiency
- Automatic checkpointing to prevent data loss
- Goroutine-safe design with proper synchronization
- Low CPU/memory footprint suitable for endpoint deployment

### Network Efficiency
- Batch transmission reduces API calls
- Configurable retry logic handles transient failures
- Health check monitoring prevents unnecessary retries
- Graceful degradation when backend unavailable

## Usage

### Command Line
```bash
# Start with default configuration
./sentinelgo-auditlogs -config ~/.sentinelgo/config.json

# Enable real-time collection
./sentinelgo-auditlogs -config config.json -realtime

# Force collection before exit
./sentinelgo-auditlogs -config config.json -force

# Verbose logging
./sentinelgo-auditlogs -config config.json -verbose
```

### Integration
The service is designed for seamless integration with the main SentinelGo agent:
- Uses existing configuration system
- Shares authentication tokens with other modules
- Follows established logging patterns
- Supports graceful shutdown coordination

## Testing

### Unit Tests
- Parser validation and normalization
- Service batch processing logic
- Checkpoint management
- HTTP transmission retry logic

### Integration Tests
- Cross-platform collector functionality
- End-to-end batch transmission
- Configuration loading and validation
- Service lifecycle management

### Performance Tests
- Large batch processing (10,000+ logs)
- Memory usage under sustained load
- Network transmission efficiency
- Checkpoint I/O performance

## Limitations and Considerations

### Windows
- Requires administrator privileges for Security event log access
- Event Log API complexity requires careful resource management
- UTF-16 encoding handling for non-ASCII events

### Linux  
- systemd journal availability varies by distribution
- File permission requirements for /var/log access
- journalctl fallback may be less efficient than native API

### macOS
- log command availability varies by macOS version
- Real-time streaming may have higher resource usage
- Crash report access requires appropriate permissions

### General
- Checkpoint file corruption handling needs improvement
- Network offline mode could be enhanced
- Memory usage could be optimized for very large batches

## Future Enhancements

1. **Native Linux systemd-journal API** - Replace journalctl fallback with direct API access
2. **Enhanced macOS OSLog integration** - Direct OSLogStore API usage
3. **Offline mode** - Local buffering when network unavailable
4. **Compression** - Batch compression for network efficiency
5. **Filtering** - Client-side log filtering to reduce transmission volume
6. **Metrics** - Collection and transmission metrics for monitoring
7. **Dynamic configuration** - Runtime configuration updates

## Dependencies

### Go Modules
- `golang.org/x/sys/windows` - Windows API bindings
- Standard library for HTTP, JSON, file I/O

### System Requirements
- **Windows:** Windows 7+ with Event Log service
- **Linux:** systemd-based distribution (optional journal support)
- **macOS:** macOS 10.12+ with log command
- **Network:** HTTPS access to Supabase Edge Functions
- **Permissions:** Log file access (typically requires elevated privileges)

## Conclusion

The SentinelGo Audit Log Collection System provides a robust, production-ready solution for cross-platform audit log collection with strong security, performance, and reliability characteristics. The modular design allows for easy extension and maintenance while maintaining compatibility with existing MDM infrastructure.
