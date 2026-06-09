> **DEPRECATED.** This document has been superseded by [`docs/08-project-overview.md`](docs/08-project-overview.md), the canonical architecture reference. It is kept here for historical context only. The ASCII-art diagrams in this older doc are affected by a UTF-8 encoding issue and may render as mojibake in some viewers. Please refer to `docs/08` for accurate, current information.

# SentinelGo System Architecture

## Overview

SentinelGo is a cross-platform system monitoring agent designed to run as a background service on Windows, macOS, and Linux systems. It provides real-time system health monitoring, automatic updates, and centralized reporting through a clean, modular architecture.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────┐
│                    SentinelGo Agent                        │
├─────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Heartbeat │  │   System    │  │     Updater         │  │
│  │   Service   │  │   Info      │  │     Service         │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Config    │  │  Lockfile   │  │   Service Manager   │  │
│  │   Manager   │  │  Manager    │  │   (kardianos)       │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────┤
│                    Platform Layer                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Windows   │  │    macOS    │  │      Linux          │  │
│  │   Service   │  │  Launchd    │  │     Systemd         │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
├─────────────────────────────────────────────────────┤
│                  External Services                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Supabase  │  │   GitHub    │  │   Event Logs        │  │
│  │   Backend   │  │   Releases  │  │   (Platform)        │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

## Core Components

### 1. Main Application (`cmd/sentinelgo/main.go`)

**Responsibilities:**
- Application entry point and lifecycle management
- Command-line argument parsing and validation
- Service installation, configuration, and management
- Graceful shutdown handling
- Cross-platform service integration

**Key Features:**
- Process locking to prevent multiple instances
- Service registration with platform-specific service managers
- Background operation with proper signal handling
- Configuration loading and validation

### 2. Configuration Manager (`internal/config/config.go`)

**Responsibilities:**
- Configuration file loading and parsing
- Environment variable handling
- Default value management
- Configuration validation

**Configuration Structure:**
```json
{
  "heartbeat_interval": "5m0s",      // String format for time.Duration
  "auto_update": false,              // Automatic update enabled/disabled
  "github_owner": "habib45",          // GitHub repository owner
  "github_repo": "SentinelGo",        // GitHub repository name
  "current_version": "v1.9.9.0",      // Current agent version
  "supabase_url": "...",             // Supabase backend URL
  "supabase_key": "...",              // Supabase API key
  "device_id": "unique-device-id"     // Auto-generated device identifier
}
```

**Configuration Locations:**
- **Windows:** `C:\SentinelGo\.sentinelgo\config.json`
- **macOS:** `/opt/sentinelgo/.sentinelgo/config.json`
- **Linux:** `/etc/sentinelgo/config.json` or `/opt/sentinelgo/.sentinelgo/config.json`

### 3. Heartbeat Service (`internal/heartbeat/heartbeat.go`)

**Responsibilities:**
- Periodic system health reporting
- Data collection and transmission
- Network communication with backend

**Payload Structure:**
```json
{
  "device_id": "unique-identifier",
  "alive": true,
  "bsid": "base-station-id",
  "os": "windows/linux/darwin",
  "uptime": 3600,
  "uptime_formatted": "1h0m0s",
  "mac_address": "00:11:22:33:44:55",
  "timestamp": "2026-02-18T12:00:00Z"
}
```

**Features:**
- Configurable heartbeat intervals
- Automatic retry with exponential backoff
- Network failure handling
- Structured logging

### 4. System Information (`internal/osinfo/osinfo.go`)

**Responsibilities:**
- System metrics collection
- Platform-specific information gathering
- Real-time system state monitoring

**Collected Metrics:**
- Operating system information (name, version, architecture)
- System uptime and boot time
- Hardware information (CPU, memory, disk)
- Network interface details
- Process information

### 5. Updater Service (`internal/updater/updater.go`)

**Responsibilities:**
- Automatic version checking
- Binary download and verification
- Atomic updates and rollback
- Update failure recovery

**Update Process:**
1. Check current version against GitHub releases
2. Download appropriate binary for platform/architecture
3. Verify binary integrity and signature
4. Perform atomic binary replacement
5. Restart service with new version

**Features:**
- Semantic versioning support
- Platform-specific binary selection
- Rollback capability on failure
- Configurable update intervals

### 6. Lockfile Manager (`internal/lockfile/lockfile.go`)

**Responsibilities:**
- Process instance management
- PID file creation and management
- Deadlock detection and recovery

**Features:**
- Cross-platform file locking
- Stale lock cleanup
- Process existence verification
- Graceful lock release

## Platform Integration

### Windows Service Integration
- **Service Manager:** Windows Service Control Manager (SCM)
- **Installation:** `sc.exe create` with proper parameters
- **Configuration:** Registry entries and service parameters
- **Logging:** Windows Event Log integration
- **Permissions:** SYSTEM account with elevated privileges

### macOS Service Integration
- **Service Manager:** Launchd (macOS native service manager)
- **Configuration:** Property list (plist) files
- **Installation:** `launchctl load/unload` commands
- **Logging:** Apple System Log (ASL) integration
- **Permissions:** Dedicated user account with limited privileges

### Linux Service Integration
- **Service Manager:** Systemd (modern Linux distributions)
- **Configuration:** Unit files with proper dependencies
- **Installation:** `systemctl enable/start/stop` commands
- **Logging:** Systemd journal integration
- **Permissions:** Dedicated `sentinelgo` user with minimal privileges

## Data Flow Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Config Load   │───▶│  Service Start  │───▶│  Main Loop      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                                        │
                       ┌─────────────────┐            │
                       │  Heartbeat      │◀───────────┤
                       │  Interval       │            │
                       └─────────────────┘            │
                                                        │
┌─────────────────┐    ┌─────────────────┐            │
│ System Info     │◀───│ Data Collection │◀───────────┤
│ Gathering       │    │                 │            │
└─────────────────┘    └─────────────────┘            │
                                                        │
┌─────────────────┐    ┌─────────────────┐            │
│ HTTP POST to    │◀───│ Payload Format   │◀───────────┤
│ Supabase        │    │                 │            │
└─────────────────┘    └─────────────────┘            │
                                                        │
                       ┌─────────────────┐            │
                       │ Update Check    │◀───────────┤
                       │ (GitHub API)    │            │
                       └─────────────────┘            │
```

## Security Architecture

### Authentication & Authorization
- **API Keys:** Supabase API key for backend communication
- **TLS/SSL:** Encrypted communication with backend services
- **File Permissions:** Restricted access to configuration and binaries

### Process Isolation
- **Dedicated User:** Service runs under dedicated user account
- **Minimal Privileges:** Principle of least privilege
- **Resource Limits:** CPU and memory usage restrictions

### Data Protection
- **No Sensitive Data:** No passwords, keys, or personal information stored
- **Secure Storage:** Configuration files with appropriate permissions
- **Network Security:** Encrypted communication channels

## Deployment Architecture

### Binary Distribution
- **Cross-Platform Builds:** Windows, macOS (Intel/ARM), Linux (AMD64/ARM64)
- **GitHub Releases:** Automated release pipeline with CI/CD
- **Version Management:** Semantic versioning with automatic updates

### Installation Methods
1. **Automated Scripts:** Platform-specific installation scripts
2. **Package Managers:** Native package formats (MSI, PKG, DEB/RPM)
3. **Manual Installation:** Direct binary deployment

### Configuration Management
- **Default Configuration:** Sensible defaults out-of-the-box
- **Environment Variables:** Override capabilities for deployment
- **Dynamic Configuration:** Runtime configuration updates

## Monitoring & Observability

### Logging Strategy
- **Structured Logging:** JSON-formatted logs with consistent fields
- **Log Levels:** DEBUG, INFO, WARN, ERROR with appropriate filtering
- **Platform Integration:** Native logging systems (Event Log, ASL, journald)

### Metrics Collection
- **System Metrics:** CPU, memory, disk, network usage
- **Application Metrics:** Heartbeat success rates, update status
- **Performance Metrics:** Response times, error rates

### Health Checks
- **Service Status:** Periodic health verification
- **Dependency Checks:** Backend connectivity validation
- **Resource Monitoring:** Memory and CPU usage tracking

## Scalability Considerations

### Horizontal Scaling
- **Multi-Instance Support:** Multiple agents per environment
- **Load Distribution:** Configurable heartbeat intervals
- **Resource Efficiency:** Minimal resource footprint

### Vertical Scaling
- **Resource Limits:** Configurable memory and CPU constraints
- **Performance Tuning:** Optimized data collection and transmission
- **Batch Processing:** Efficient data aggregation and reporting

## Reliability & Fault Tolerance

### Error Handling
- **Graceful Degradation:** Continue operation with partial failures
- **Retry Mechanisms:** Exponential backoff for network operations
- **Circuit Breakers:** Prevent cascade failures

### Recovery Strategies
- **Automatic Restart:** Service manager integration for auto-recovery
- **State Persistence:** Configuration and state preservation
- **Rollback Capability:** Version rollback on update failures

### High Availability
- **Redundant Services:** Multiple backend endpoints support
- **Failover Logic:** Automatic fallback to alternative endpoints
- **Health Monitoring:** Continuous service health verification

## Future Architecture Enhancements

### Planned Features
1. **Plugin Architecture:** Extensible monitoring modules
2. **Configuration Management:** Centralized configuration service
3. **Advanced Metrics:** Custom metric collection and reporting
4. **Security Enhancements:** Certificate-based authentication

### Scalability Improvements
1. **Microservices Architecture:** Component-based service separation
2. **Event-Driven Design:** Asynchronous processing capabilities
3. **Caching Layer:** Local caching for improved performance
4. **Load Balancing:** Multiple backend endpoint support

### Integration Capabilities
1. **API Gateway:** Centralized API management
2. **Message Queues:** Asynchronous communication patterns
3. **Database Integration:** Local data storage capabilities
4. **Third-Party Integrations:** Extended monitoring service support

---

This architecture document provides a comprehensive overview of SentinelGo's design, components, and operational characteristics. The modular design ensures maintainability, scalability, and reliability across all supported platforms.
