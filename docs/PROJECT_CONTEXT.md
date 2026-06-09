# SentinelGo

> **Status: Superseded.** This document is preserved as a historical snapshot
> of an early architecture sketch. It contains several inaccuracies that
> have since been corrected (phantom file paths, a personal-org
> `habib45` reference, wrong on-disk config locations, an incorrect
> single-table agent_heartbeats schema, and a stale "Known Technical
> Debt" list that no longer reflects the codebase).
>
> For the current, authoritative project description, see
> [`docs/08-project-overview.md`](08-project-overview.md) (architecture,
> package layout, runtime flow, build) and the per-module docs:
>
> - [`docs/01-main-module.md`](01-main-module.md) — `cmd/sentinelgo/` CLI
> - [`docs/02-config-module.md`](02-config-module.md) — `internal/config/`
> - [`docs/04-lockfile-module.md`](04-lockfile-module.md) — `internal/lockfile/`
> - [`docs/05-osinfo-module.md`](05-osinfo-module.md) — `internal/osinfo/`
> - [`docs/06-service-module.md`](06-service-module.md) — `internal/service/{auth,agent}/`
> - [`docs/07-updater-module.md`](07-updater-module.md) — `internal/updater/`
> - [`docs/audit-logs-architecture.md`](audit-logs-architecture.md) — audit log pipeline
> - [`docs/agent-commands-guide.md`](agent-commands-guide.md) — CLI flags
> - [`docs/agent-script-download.md`](agent-script-download.md) — task script download
>
> The body of this file is retained below for reference only.

---

## 1. Overview

SentinelGo is a cross-platform system monitoring agent written in Go that collects OS-level metrics and reports them to a Supabase backend via periodic heartbeats. The agent runs as a native system service on Windows, Linux (systemd), and macOS (launchd) and includes automatic self-update capabilities.

**Core Purpose**: Provide real-time system monitoring and remote management capabilities for distributed fleets of machines.

**Main User Roles**:
- **System Administrators**: Deploy and monitor fleets of machines
- **DevOps Engineers**: Integrate system monitoring into CI/CD pipelines
- **Security Teams**: Monitor system integrity and detect anomalies

## 2. Tech Stack

**Backend Framework**: Go 1.22 (Pure Go application)
**Frontend Framework**: None (CLI-based agent)
**Database**: Supabase (PostgreSQL with REST API)
**Authentication Method**: JWT tokens with agent UUID/secret credentials
**Deployment Platform**: Cross-platform (Windows, Linux, macOS)
**External Services**: 
- Supabase (authentication and data storage)
- GitHub Releases (automatic updates)

**Dependencies**:
- `github.com/kardianos/service v1.2.2` - Cross-platform service management
- `github.com/shirou/gopsutil/v3 v3.24.5` - System metrics collection

## 3. Architecture

**Type**: Clean Architecture with modular design

**High-level System Design**:
```
┌─────────────────────────────────────────────────────────┐
│                 SentinelGo Agent                    │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │   Main      │  │  Config     │  │  Lockfile   │ │
│  │   Module    │  │  Module     │  │  Module     │ │
│  │             │  │             │  │             │ │
│  │ • CLI      │  │ • JSON      │  │ • Process   │ │
│  │ • Service  │  │ • Env       │  │   Locking   │ │
│  │ • Process  │  │ • Security  │  │ • PID       │ │
│  └─────────────┘  └─────────────┘  └─────────────┘ │
│                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │ Heartbeat   │  │  OS Info    │  │  Service    │ │
│  │ Module      │  │ Module      │  │ Module      │ │
│  │             │  │             │  │             │ │
│  │ • System    │  │ • Hardware  │  │ • JWT Auth  │ │
│  │ • Report    │  │ • Metrics   │  │ • Agent Mgmt│ │
│  │ • API       │  │ • Network   │  │ • Hardware  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘ │
│                                                     │
│  ┌─────────────┐                                    │
│  │ Updater     │                                    │
│  │ Module      │                                    │
│  │             │                                    │
│  │ • GitHub    │                                    │
│  │ • Download  │                                    │
│  │ • Update    │                                    │
│  └─────────────┘                                    │
└─────────────────────────────────────────────────────────┘
```

**Request Lifecycle Flow**:
1. **Startup**: Load config → Acquire process lock → Initialize services
2. **Authentication**: Agent registration → JWT token exchange → Store credentials
3. **Monitoring Loop**: Collect system info → Send heartbeat → Wait interval
4. **Update Check**: Daily GitHub check → Download if newer → Replace binary → Restart

## 4. Folder Structure

```
SentinelGo/
├── cmd/sentinelgo/          # Application entry point
│   └── main.go            # Main CLI interface and service orchestration
├── internal/               # Private application code
│   ├── config/            # Configuration management
│   │   └── config.go     # JSON config, env vars, credential storage
│   ├── heartbeat/         # System status reporting
│   │   └── heartbeat.go  # Heartbeat payload generation and API calls
│   ├── lockfile/          # Process instance management
│   │   └── lockfile.go   # File-based locking and PID tracking
│   ├── osinfo/            # System information collection
│   │   └── osinfo.go    # Hardware metrics and system data
│   ├── service/           # Authentication and agent management
│   │   ├── authService.go    # JWT authentication with Supabase
│   │   └── agentService.go   # Agent info management and hardware detection
│   └── updater/           # Automatic update management
│       └── updater.go    # GitHub releases, binary download, process management
├── docs/                  # Project documentation
├── doc/                   # Installation guides
├── scripts/               # Build and deployment scripts
├── build/                 # Compiled binaries by platform
├── release/               # Release packages and assets
├── .github/workflows/     # CI/CD pipeline definitions
├── go.mod                # Go module definition
├── go.sum                # Dependency checksums
├── Makefile              # Build automation
├── .env.example          # Environment variable template
└── README.md             # Project overview and quick start
```

## 5. Environment Variables

**Required Variables**:
- `SUPABASE_URL` - Supabase project URL (e.g., `https://your-project.supabase.co`)
- `SUPABASE_KEY` - Supabase anonymous API key for database access
- `API_TOKEN` - API token for authentication (alternative to agent credentials)

**Optional Variables**:
- `AGENT_UUID` - Agent unique identifier for registration
- `AGENT_SECRET` - Agent secret key for authentication
- `HEARTBEAT_INTERVAL` - Heartbeat frequency override (default: 5m)
- `GITHUB_OWNER` - GitHub repository owner (default: habib45)
- `GITHUB_REPO` - GitHub repository name (default: SentinelGo)
- `AUTO_UPDATE` - Enable automatic updates (default: false)

## 6. API Documentation

**Base URL**: `{SUPABASE_URL}/rest/v1`

**Authentication Method**: JWT Bearer tokens with Supabase API key fallback

**Endpoints**:

**Authentication**:
- `POST /functions/v1/agent-login` - Agent authentication and token exchange
- `POST /functions/v1/agent-refresh` - JWT token refresh

**Agent Management**:
- `PATCH /agents?agent_uuid=eq.{uuid}` - Update agent information
- `GET /agents?agent_uuid=eq.{uuid}&select=*` - Retrieve agent details
- `PATCH /agents?agent_uuid=eq.{uuid}` - Update agent status

**Heartbeat**:
- `POST /agent_heartbeats` - Submit system heartbeat

**Request/Response Format**:

**Agent Login Request**:
```json
{
  "agent_uuid": "550e8400-e29b-41d4-a716-446655440000",
  "agent_secret": "secure-agent-secret-key"
}
```

**Agent Login Response**:
```json
{
  "success": true,
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "expires_in": 3600,
  "agent": {
    "id": "12345",
    "agent_uuid": "550e8400-e29b-41d4-a716-446655440000",
    "status": "active"
  }
}
```

**Heartbeat Request**:
```json
{
  "agent_id": "12345",
  "private_ip": "192.168.1.100",
  "public_ip": "203.0.113.1",
  "disk_free": 107374182400,
  "issues_count": 0,
  "last_restarted": "2024-01-15T10:30:45Z"
}
```

**Error Handling Pattern**:
- HTTP status codes (400, 401, 403, 500)
- JSON error responses with descriptive messages
- Exponential backoff retry for transient failures
- Structured error wrapping with context

## 7. Database Schema

**Tables**:

**agents**:
```sql
CREATE TABLE agents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_uuid VARCHAR(255) UNIQUE NOT NULL,
  status VARCHAR(50) DEFAULT 'inactive',
  hostname VARCHAR(255),
  computer_name VARCHAR(255),
  os_name VARCHAR(100),
  os_version VARCHAR(100),
  osquery_version VARCHAR(50),
  total_ram BIGINT,
  cpu_info TEXT,
  cpu_cores INTEGER,
  cpu_usage DECIMAL(5,2),
  mac_address VARCHAR(17),
  serial_number VARCHAR(255),
  hardware_model VARCHAR(255),
  manufacturer VARCHAR(255),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);
```

**agent_heartbeats**:
```sql
CREATE TABLE agent_heartbeats (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id UUID REFERENCES agents(id),
  private_ip VARCHAR(45),
  public_ip VARCHAR(45),
  disk_free BIGINT,
  issues_count INTEGER DEFAULT 0,
  last_restarted TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW()
);
```

**Key Fields**:
- `agent_uuid` - Unique agent identifier for authentication
- `agent_id` - Foreign key relationship to agents table
- `status` - Agent lifecycle state (active, inactive, error)

**Indexes**:
- `UNIQUE INDEX` on `agents.agent_uuid`
- `INDEX` on `agent_heartbeats.agent_id` for performance
- `INDEX` on `agent_heartbeats.created_at` for time-series queries

## 8. Business Logic Flow

**Agent Registration**:
1. Load configuration with agent UUID/secret
2. Call `/functions/v1/agent-login` with credentials
3. Receive JWT access and refresh tokens
4. Store tokens in configuration file
5. Update agent information in database with hardware details

**Heartbeat Reporting**:
1. Collect system metrics (CPU, memory, disk, network)
2. Generate heartbeat payload with current system state
3. Send POST to `/agent_heartbeats` with JWT authentication
4. Handle API errors with retry logic
5. Wait for configured interval (default: 5 minutes)

**Automatic Updates**:
1. Daily check of GitHub releases API
2. Compare latest release tag with current version
3. Download appropriate binary for current OS/architecture
4. Stop existing SentinelGo processes
5. Replace binary atomically
6. Restart service with new version
7. Update configuration with new version

**Process Management**:
1. Create version-specific lock file on startup
2. Check for existing locks and stale processes
3. Acquire exclusive lock or exit with error
4. Release lock on graceful shutdown

## 9. External Integrations

**Supabase**:
- **Authentication**: JWT token management and agent registration
- **Database Storage**: Agent information and heartbeat data
- **REST API**: CRUD operations on agents and heartbeats
- **Real-time**: Potential for real-time monitoring dashboards

**GitHub**:
- **Release Management**: Automatic update detection and download
- **Version Control**: Source code and release tagging
- **CI/CD**: Automated builds and releases via GitHub Actions

**System Services**:
- **Windows Service API**: Native Windows service integration
- **systemd**: Linux service management and logging
- **launchd**: macOS service integration with plist management

## 10. Security Considerations

**Auth Flow**:
1. **Agent Registration**: UUID/secret based initial authentication
2. **JWT Tokens**: Short-lived access tokens with refresh capability
3. **Token Storage**: Encrypted storage in configuration files
4. **Token Refresh**: Automatic renewal before expiration

**Middleware**:
- **HTTPS Only**: All external communication over encrypted channels
- **Request Validation**: Input sanitization and validation
- **Rate Limiting**: Built-in retry limits and backoff
- **Error Sanitization**: No sensitive data in error messages

**Validation Approach**:
- **Configuration Validation**: Validate all config values on load
- **Payload Validation**: Ensure heartbeat data integrity
- **Version Validation**: Verify binary integrity during updates
- **Process Isolation**: Single instance enforcement via file locking

**Role-based Access**: None implemented (single agent role)

## 11. Deployment & Dev Setup

**Local Development**:
```bash
# Clone repository
git clone https://github.com/habib45/SentinelGo.git
cd SentinelGo

# Install dependencies
go mod download

# Copy environment template
cp .env.example .env

# Edit configuration
nano .env

# Build for current platform
make build

# Run in foreground
./bin/sentinelgo -run
```

**Build Process**:
```bash
# Development build
make build

# Release build (all platforms)
make release VERSION=v1.0.0

# Quality checks
make quality-check
make test
```

**Production Deployment**:
```bash
# Install as service (requires admin/root)
sudo ./sentinelgo -install

# Or manual service installation
# Windows: Use Windows Service API
# Linux: Install systemd service file
# macOS: Install launchd plist

# Verify service status
./sentinelgo -status
```

**Configuration Locations**:
- Windows: `C:\ProgramData\sentinelgo\config.json`
- Linux: `/etc/sentinelgo/config.json`
- macOS: `/etc/sentinelgo/config.json`

## 12. Windows Event Log Collection

**Overview**: SentinelGo includes comprehensive Windows Event Log collection capabilities for security auditing and system monitoring. The collector monitors 11 specialized channels covering authentication, system operations, applications, and Microsoft services.

**Architecture**: Clean Architecture with channel-based filtering
- **Location**: `internal/auditlogs/collector/collector_windows.go`
- **Dynamic Source Generation**: Channel names automatically generate source identifiers
- **Severity Mapping**: Windows Event Levels → Standard severity strings

**Channel Coverage**:

**Security Channel (3 Groups)**:
- **Authentication**: Logon/Logoff events (4624, 4625, 4634, 4648, 4672)
- **User Management**: Account operations (4720-4738)  
- **Policy & Network**: Process creation, network/object access (4656-4739, 5156-5157)

**System Channel (2 Groups)**:
- **General**: Critical, Error, Warning, Information events (Level 1-4)
- **Time Service**: Time synchronization & timezone events (24, 35)

**Application Channel**:
- **Applications**: Critical, Error, Warning events (Level 1-3)
- **License Issues**: Windows activation failures (8198)

**Microsoft Services (6 Channels)**:
- **Windows Defender**: All antivirus events
- **PowerShell**: Script execution and module operations (4103-4106)
- **Task Scheduler**: Task creation, execution, failures (100-201)
- **Windows Firewall**: Firewall rules and connections (Level 1-3)
- **Remote Desktop**: RDP connections and disconnections (1149, 261, 1158)
- **Group Policy**: Policy application and processing (Level 1-3)

**Severity Mapping**:
```
Level 1 (Critical)   → "critical"
Level 2 (Error)      → "high"
Level 3 (Warning)    → "medium"
Level 4 (Information) → "info"
Level 5 (Verbose)    → "info"
Default              → "info"
```

**Dynamic Source Names**:
- `Security` → `windows_security`
- `System` → `windows_system`
- `Microsoft-Windows-Windows Defender/Operational` → `windows_microsoft_windows_windows_defender_operational`

**Event Processing**:
- **Collection**: Windows Event Log API with XPath filtering
- **Parsing**: XML event extraction and field mapping
- **Classification**: Dynamic event type and severity determination
- **Storage**: Structured log entries with metadata

**Configuration**:
```go
var channels = []eventChannel{
    {
        name:   "Security",
        source: generateSource("Security"),
        query:  "*[System[(EventID=4624 or EventID=4625 or EventID=4634 or EventID=4648 or EventID=4672)]]",
    },
    // ... additional channels
}
```

**Compliance Benefits**:
- **Complete Audit Trail**: All security-relevant events captured
- **Regulatory Compliance**: Meets common audit requirements
- **Incident Response**: Detailed event history for investigations
- **Operational Visibility**: Comprehensive system health monitoring

## 13. Known Technical Debt or Improvements

**Current Limitations**:

**IP Detection**: Placeholder implementation returns localhost
- **Improvement**: Implement actual private/public IP detection
- **Impact**: Limited network visibility in heartbeats

**Hardware Detection**: Limited Linux hardware information collection
- **Improvement**: Implement comprehensive Linux hardware detection
- **Impact**: Incomplete system inventory data

**Error Handling**: Basic error wrapping without structured error types
- **Improvement**: Implement structured error types with error codes
- **Impact**: Limited error classification and handling

**Testing**: No comprehensive test suite
- **Improvement**: Add unit tests, integration tests, and end-to-end tests
- **Impact**: Reduced confidence in code reliability

**Configuration**: Limited validation and environment variable support
- **Improvement**: Add comprehensive configuration validation framework
- **Impact**: Potential runtime configuration errors

**Security**: No binary signature verification for updates
- **Improvement**: Implement cryptographic binary verification
- **Impact**: Security vulnerability in update process

**Monitoring**: No built-in metrics collection or health endpoints
- **Improvement**: Add Prometheus metrics and health check endpoints
- **Impact**: Limited observability for operations

**Documentation**: API documentation not machine-readable
- **Improvement**: Add OpenAPI/Swagger specification
- **Impact**: Difficult integration for external tools

**Performance**: No connection pooling or caching strategies
- **Improvement**: Implement HTTP client pooling and response caching
- **Impact**: Suboptimal resource usage

**Logging**: Basic logging without structured format
- **Improvement**: Implement structured logging with levels and correlation IDs
- **Impact**: Difficult troubleshooting and monitoring

**Event Log Collection**: Windows-only implementation
- **Improvement**: Add Linux syslog and macOS log collection
- **Impact**: Limited cross-platform audit capabilities
