> **DEPRECATED.** This document has been superseded by [`docs/08-project-overview.md`](docs/08-project-overview.md), the canonical architecture and runtime-flow reference. It is kept here for historical context only. Please refer to `docs/08` for accurate, current information.

Run the application using the following execution flow and automation rules:

## SERVICE MANAGEMENT & LIFECYCLE

1. **Auto-start** the application immediately after installation.

2. **Auto-run** the application on:
   - system boot
   - computer restart
   - user login
   without any human interaction.

3. **Service Management** (via `kardianos/service`):
   - Install as system service (Windows: Service, Linux: systemd, macOS: launchd)
   - Implement process locking (`internal/lockfile`) to prevent multiple instances
   - Support service operations: install, uninstall, start, stop, restart
   - Graceful shutdown with proper resource cleanup via context cancellation
   - Signal handling (SIGTERM, SIGINT) for clean termination

## CONFIGURATION & AUTHENTICATION

4. **On Application Startup** (`cmd/sentinelgo/main.go`):
   - Load `config.json` from platform-specific path with validation
   - Validate required fields: `supabase_url`, `device_id`, `agent_id`, tokens
   - Read configuration:
     - `access_token` - JWT access token
     - `refresh_token` - JWT refresh token
     - `update_interval` - Software sync interval (default: 5m)
     - `log_flush_interval` - Audit log collection interval (default: 5m)
     - `task_polling_interval` - Task polling interval (default: 5m)
     - `task_execution_interval` - Task execution interval (default: 30s)
     - Feature flags: `auto_update`, `software_sync_enabled`, `audit_logs_enabled`, `enable_task_polling`
   - Generate `device_id` and `agent_id` if not present

5. **Initialize MainIntegration** (`internal/main_integration.go`):
   - Create MainIntegration instance with config
   - Initialize EnhancedAuth for token management
   - Initialize Service for Supabase authentication
   - Initialize Scheduler for task coordination
   - Initialize TaskManager for remote task polling/execution

6. **Enhanced Authentication Flow** (`internal/auth/enhanced_auth.go`):
   - **Session Initialization**:
     - Load stored tokens from config
     - Initialize Supabase client session
   - **Token Validation**:
     - Check access_token expiration
     - Preemptively refresh if expiring soon (< 5 minutes)
   - **Token Refresh** (if expired/invalid):
     - Use refresh_token to request new access_token
     - Implement exponential backoff retry (max 3 attempts: 1s, 2s, 4s intervals)
     - Update session with new tokens
     - Save new access_token to config.json with atomic write
   - **Failure Handling**:
     - Circuit breaker pattern (disable for 5 minutes after 5 consecutive failures)
     - Structured logging for authentication failures
     - Continue operation without crashing
     - Individual tasks handle token refresh independently

## TASK EXECUTION & SCHEDULING

7. **Centralized Task Scheduler** (`internal/scheduler/scheduler.go`):
   
   The scheduler manages all background tasks with dependency resolution and health monitoring:

   **Task Dependency Chain**:
   ```
   auto-update (24h)
       ↓
   agent-info-update (1h)
       ↓
   software-sync (5m)
       ↓
   audit-logs (5m)
   ```

   **Task Execution Flow**:
   
   a. **Auto-Update Task** (`handleAutoUpdate`):
      - Check latest version from GitHub releases API
      - Compare with current version
      - Verify update integrity with SHA256 checksums
      - Download binary for current platform (linux-amd64, darwin-amd64, darwin-arm64, windows-amd64)
      - Stop all older SentinelGo processes before update
      - Atomic binary replacement with backup creation
      - Restart application if update successful
      - Rollback on failure
      - Retry policy: max 3 attempts with exponential backoff
      - Interval: 24 hours (configurable)
      - Enabled: Based on `auto_update` config flag

   b. **Agent Information Update Task** (`handleAgentInfoUpdate`):
      - Collect comprehensive system information via `osinfo.Collect()`:
        - Hostname, Serial Number, Hardware Model
        - CPU info (model, cores, usage, architecture)
        - Memory (total, used, free, usage %)
        - Disk info (capacity, encryption status, manufacturer)
        - Network adapters (MAC, IPv4, IPv6, connection status)
        - GPUs, RAMs, Displays, Audio Devices, Printers
        - Peripherals (USB devices, built-in hardware)
        - Firmware (type, vendor, version), TPM version
        - OS information (name, version, timezone, last boot)
        - Local users and groups
        - Battery condition, FQDN, Chassis type
      - Call `agent_push_inventory` RPC to update agent record
      - Retry with exponential backoff on failure
      - Interval: 1 hour (configurable)
      - Dependency: Runs after auto-update
      - Always enabled

   c. **Software Sync Task** (`handleSoftwareSync`):
      - Scan installed software using platform-specific methods:
        - **Windows**: Registry (HKLM/HKCU Uninstall keys), WMI queries
        - **Linux**: dpkg, rpm, snap, flatpak, AppImage detection
        - **macOS**: Applications folder, Homebrew, system_profiler
      - Extract software metadata:
        - Name, Version, Publisher, Install Date
        - Install Location, Size, Type (application/system)
      - Call `agent_upsert_software` RPC to sync software list
      - Batch processing for large software lists
      - Incremental updates (only changed software)
      - Retry failed uploads with backoff
      - Interval: 5 minutes (configurable via `update_interval`)
      - Enabled: Based on `software_sync_enabled` config flag
      - Dependency: Runs after agent-info-update

   d. **Audit Logs Task** (`handleAuditLogs`):
      - Initialize LoggingIntegration service
      - Collect audit logs from multiple sources:
        - **System Logs**: Boot events, shutdown, system updates
        - **Security Logs**: Login attempts, sudo usage, authentication
        - **Network Logs**: Connection events, firewall changes
        - **MDM Logs**: Policy changes, compliance events
      - Parse logs using platform-specific parsers:
        - **Windows**: Event Log API
        - **Linux**: journalctl, syslog, auth.log
        - **macOS**: unified logging system (log show)
      - Buffer logs with checkpoint persistence
      - Batch upload via `agent_insert_audit_logs_batch` RPC
      - Compress large log batches
      - Respect log retention policies
      - Real-time subscription for critical events
      - Interval: 5 minutes (configurable via `log_flush_interval`)
      - Enabled: Based on `audit_logs_enabled` config flag
      - Dependency: Runs after software-sync

8. **Task Manager** (`internal/service/task_manager.go`):
   
   Handles remote task polling and execution from Supabase:

   **Task Polling Service**:
   - Poll `agent_tasks` table for pending tasks
   - Filter by agent_id and status='pending'
   - Store tasks in local SQLite database
   - Track task execution history
   - Interval: 5 minutes (configurable via `task_polling_interval`)

   **Task Executor Service**:
   - Execute pending tasks from local database
   - Support task types: script execution, configuration updates, commands
   - Update task status (pending → running → completed/failed)
   - Report execution results back to Supabase
   - Timeout handling and cancellation support
   - Interval: 30 seconds (configurable via `task_execution_interval`)

   **Sequential Execution**:
   - Poll tasks first
   - Then execute pending tasks
   - Prevents race conditions
   - Enabled: Based on `enable_task_polling` config flag

9. **Scheduler Features**:
   - Single goroutine-based scheduler with context cancellation
   - Dependency resolution using topological sort
   - Circular dependency detection
   - Task health monitoring (running status, last run time)
   - Dynamic interval updates from config changes
   - Graceful task shutdown with 30-second timeout
   - Atomic task execution (prevents concurrent runs)
   - Task status reporting via `GetTaskStatus()`

## RELIABILITY & ERROR HANDLING

10. **Application Resilience**:
    - Runs continuously in background as system service
    - Auto-recovers from failures with service restart policies
    - Retries failed requests with exponential backoff (max 3-5 attempts)
    - Maintains persistent session across restarts
    - Structured logging with levels (INFO, WARN, ERROR, DEBUG) via `log` package
    - Circuit breaker pattern for authentication failures
    - Context-based cancellation for graceful shutdown
    - WaitGroup synchronization for goroutine management
    - Memory leak prevention through proper resource cleanup
    - Panic recovery in critical goroutines

11. **Error Handling Patterns**:
    - All tasks return errors for proper logging
    - Failed tasks don't crash the application
    - Task failures logged with context
    - Retry logic with backoff for transient failures
    - Checkpoint persistence for audit log collection
    - Atomic file operations for config updates
    - Database transaction rollback on errors

## SECURITY & COMPLIANCE

12. **Security Measures**:
    - **Token Storage**: Secure file permissions (0600) for config.json
    - **TLS Verification**: All HTTPS requests verify certificates
    - **Request Timeouts**: 30-second default timeout for all HTTP requests
    - **Input Validation**: Validate all configuration values on load
    - **Audit Logging**: All security-relevant operations logged
    - **JWT Tokens**: Use Supabase JWT for authentication
    - **RPC Security**: All RPC calls authenticated with access_token
    - **Process Isolation**: Single instance via lockfile

13. **Configuration Security**:
    - Validate configuration on startup via `ValidateConfiguration()`
    - Atomic writes for config updates (write to temp, then rename)
    - Secure default values for all settings
    - Platform-specific config paths:
      - **Windows**: `%PROGRAMDATA%\SentinelGo\config.json`
      - **Linux**: `/etc/sentinelgo/config.json`
      - **macOS**: `/Library/Application Support/SentinelGo/config.json`
    - Generate device_id and agent_id if missing
    - Never log sensitive tokens (truncate in logs)

## MONITORING & OBSERVABILITY

14. **Logging & Monitoring**:
    - Structured logging with timestamps
    - Task execution status logging
    - Authentication events logged
    - Error logging with stack context
    - Task health monitoring via `GetTaskStatus()`
    - Checkpoint persistence for audit logs
    - Statistics tracking for log collection/upload
    - Real-time event subscription for critical logs

15. **Command-Line Tools**:
    - `--status`: Show running processes and versions
    - `--version`: Display version information
    - `--software-list`: Show installed software
    - `--software-list-json`: JSON output for software
    - `--collect-logs`: Force immediate log collection
    - `--upload-logs`: Force upload of pending logs
    - `--logging-stats`: Show logging statistics
    - `--audit-logs-status`: Show audit logs service status
    - `--agent-task-polling`: Show task polling status
    - `--agent-task-execution`: Show task execution status

16. **Never require manual interaction after installation**.

## CROSS-PLATFORM COMPATIBILITY

17. **Platform-Specific Implementation**:
    - **Windows**: 
      - Service integration via kardianos/service
      - Registry-based software detection
      - Event Log API for audit logs
      - PowerShell commands for system info
      - WMI queries for hardware details
    - **Linux**: 
      - systemd service integration
      - dpkg/rpm/snap/flatpak software detection
      - journalctl/syslog for audit logs
      - DMI/sysfs for hardware info
      - Standard timezone support
    - **macOS**: 
      - launchd service integration
      - Applications folder scanning
      - Unified logging system (log show)
      - system_profiler for hardware
      - macOS-specific permissions
    - Use build tags (`_windows.go`, `_linux.go`, `_darwin.go`) for platform-specific code
    - Consistent behavior across all supported platforms
    - Runtime OS detection via `runtime.GOOS`

## ARCHITECTURE COMPONENTS

18. **Key Components**:
    - `cmd/sentinelgo/main.go` - Application entrypoint and CLI
    - `internal/main_integration.go` - MainIntegration orchestrator
    - `internal/scheduler/scheduler.go` - Task scheduler with dependencies
    - `internal/service/task_manager.go` - Remote task polling/execution
    - `internal/service/agentService.go` - Agent info updates
    - `internal/service/software_sync.go` - Software synchronization
    - `internal/logging/logging.go` - Audit log collection
    - `internal/auth/enhanced_auth.go` - Authentication management
    - `internal/config/config.go` - Configuration management
    - `internal/osinfo/` - System information collection
    - `internal/updater/` - Auto-update functionality
    - `internal/lockfile/` - Process locking

19. **Data Flow**:
    ```
    main.go
      ↓
    MainIntegration.Start()
      ↓
    ├─ EnhancedAuth (token management)
    ├─ Scheduler (task coordination)
    │   ├─ Auto-Update → GitHub API
    │   ├─ Agent Info → agent_push_inventory RPC
    │   ├─ Software Sync → agent_upsert_software RPC
    │   └─ Audit Logs → agent_insert_audit_logs_batch RPC
    └─ TaskManager (remote tasks)
        ├─ TaskPollingService → agent_tasks table
        └─ TaskExecutorService → Execute & Report
    ```

## DEPLOYMENT & OPERATIONS

20. **Installation**:
    - Run `./sentinelgo --install` to install as service
    - Service starts automatically on installation
    - Config file created at platform-specific location
    - Process lock file prevents multiple instances

21. **Uninstallation**:
    - Run `./sentinelgo --uninstall` to remove service
    - Service stopped before uninstallation
    - Config and data files remain for reinstallation

22. **Updates**:
    - Automatic updates via GitHub releases (if enabled)
    - Manual updates: replace binary and restart service
    - Rollback capability via backup creation
    - Version verification via checksums

