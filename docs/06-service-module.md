# Service Module Documentation

> **Canonical reference:** the architecture, runtime flow, and
> package layout are in
> [`docs/08-project-overview.md`](08-project-overview.md). The
> service entry point and CLI dispatch are in
> [`docs/01-main-module.md`](01-main-module.md). The config keys
> referenced here (`supabase_url`, `access_token`, `agent_id`,
> etc.) are documented in [`docs/02-config-module.md`](02-config-module.md).
>
> The on-page text below is the historical, in-depth reference for
> `internal/service/auth` and `internal/service/agent`. It has
> surgical corrections for the real package layout, filenames, and
> flag names, but is otherwise the original deep-dive.

## Overview

The service module (`internal/service/`) holds the agent's backend-facing
services. Every one of them reaches Supabase through a single client package,
`internal/supabase`.

- `internal/supabase/` — the only Supabase client: PostgREST RPCs, Storage
  downloads, GoTrue token refresh and edge functions.
- `internal/service/auth/` — session lifecycle: agent-login, token refresh,
  recovery after a 401, circuit breaker.
- `internal/service/agent/` — periodic inventory upload
  (`agent_enqueue_inventory`).
- `internal/service/rpcutil/` — `PostEnqueue` and the shared retry policy for
  the `agent_enqueue_*` RPCs.

## Supabase client (`internal/supabase`)

**Rule: all Supabase access goes through `internal/supabase`.** Do not add
HTTP calls to `/rest/v1`, `/storage/v1`, `/auth/v1` or `/functions/v1`
anywhere else, and do not add the community Go SDKs back (they have no context
support, postgrest-go never checks the HTTP status, and storage-go buffers
whole downloads in memory and has no license file).

| Operation | Request | `apikey` | `Authorization` |
|---|---|---|---|
| `RPC(ctx, fn, params, out, opts...)` | `POST /rest/v1/rpc/<fn>` | anon key | `Bearer <access token>` |
| `Download(ctx, bucket, path, authenticatedPrefix, w, limit)` | `GET /storage/v1/object/[authenticated/]<bucket>/<path>` | anon key | `Bearer <access token>` |
| `RefreshSession(ctx, refreshToken)` | `POST /auth/v1/token?grant_type=refresh_token` | anon key | none |
| `InvokeFunction(ctx, name, body, out)` | `POST /functions/v1/<name>` | anon key | none |

- **Construction.** `supabase.FromConfig(cfg)` reads the access token through
  `cfg.GetAccessToken()` on every request, so a refreshed token is used
  immediately. `supabase.New(baseURL, anonKey, tokenFunc)` is the general form.
- **Transports.** Two shared, pooled clients (30 s for API calls, 10 min for
  downloads and edge functions). Never build an `http.Client` per request.
- **Errors.** Any non-2xx response is a `*supabase.APIError` carrying the
  status, the PostgREST/Storage/GoTrue error code and a body capped at 4 KB.
  It never contains headers or tokens. Classify with `supabase.IsUnauthorized`
  (401, or `PGRST301/302/303`, `InvalidJWT`, `bad_jwt` on any status),
  `IsForbidden` (403 / `42501`), `IsNotFound` and `StatusCode`.
- **Downloads** stream to the writer and fail with `supabase.ErrTooLarge`
  rather than truncating. Storage URLs are concatenated verbatim, with no
  escaping, and pinned by golden tests.
- **No retries, no token refresh.** Retry policy stays at the call sites, and
  401 recovery goes through `auth.Service.DoWithAuthRetry`. The package must
  not import `internal/service/auth`.

The expected gateway responses, and the staging checklist that confirms them,
are in [`docs/supabase-api-contract.md`](supabase-api-contract.md). Tests use
the `internal/supabase/supabasetest` fake, which records requests and can
simulate an expired JWT and refresh-token rotation.

## Authentication service (`internal/service/auth`)

### Session lifecycle

1. **Startup.** `NewService(supabaseURL, anonKey)`. If the stored access
   token is still valid, `InitSession` reuses it (no network call); otherwise
   `Login` runs agent-login.
2. **Agent-login.** `Login` calls the `agent-login` edge function with
   `agent_id` / `agent_secret`, stores the new pair with `cfg.SetTokens` and
   persists it atomically. HTTP 401/403 returns `ErrLoginRejected` (the agent
   needs re-provisioning; reporting pauses). 429 is not retried, because each
   attempt extends the server's lockout. Other failures are retried up to 3
   times.
3. **Token refresh.** `RefreshToken` exchanges the refresh token via
   `supabase.RefreshSession` (anon `apikey`, no bearer). Supabase rotates the
   refresh token on every refresh, so the new pair is persisted immediately;
   failing to persist is treated as a refresh failure. A 4xx refresh
   (`invalid_grant`, `refresh_token_not_found`, already used) is terminal and
   falls straight through to agent-login. Network errors and 5xx are retried.
   Refresh is single-flight: concurrent callers wait for the one in flight.
4. **Proactive refresh.** The scheduler refreshes the token 5 minutes before
   it expires.

### Recovering from a 401

`DoWithAuthRetry(ctx, cfg, fn)` is the one 401 pattern every reporting path
uses. If `fn` fails with `IsUnauthorized`, it calls `Recover` (refresh, then
agent-login) and retries `fn` exactly once. A 403 is never recovered.

- `Recover` is single-flight and gated by a circuit breaker (opens after 5
  consecutive failures, for 5 minutes).
- **Recover-storm guard.** A recovery within 60 s of a successful one is
  refused (`ErrRecoveryCooldown`), and a request that is still 401 straight
  after a successful recovery counts as a breaker failure. Without this, a
  token the backend keeps rejecting (for example because of clock skew) would
  loop 401 → login → 401 until agent-login rate-limits.
- `Healthy()` is false while the breaker is open or the credentials were
  rejected. Reporting tasks check it and pause instead of firing requests that
  are guaranteed to 401.

### Token access

`config.Config.AccessToken` / `RefreshToken` are only read and written through
`GetAccessToken`, `GetRefreshToken` and `SetTokens`, which hold the config's
token lock. There is no `-race` CI job (it would need cgo), so
`internal/config/tokenaccess_test.go` enforces this structurally: it
type-checks the module for linux, darwin and windows and fails on any direct
field access outside `internal/config`.

### The CLI never refreshes

Refreshing rotates the refresh token, and that revokes the token family the
running service holds. So CLI commands use the stored access token, and if it
is rejected they log in with `LoginInMemory`, which updates the in-memory
config only and never writes it.

## Agent Service (agentService.go)

### 1. Agent Update Payload

#### Agent Information Structure
```go
type AgentUpdatePayload struct {
    Status         string  `json:"status"`
    Hostname       string  `json:"hostname"`
    ComputerName   string  `json:"computer_name"`
    OSName         string  `json:"os_name"`
    OSVersion      string  `json:"os_version"`
    OSqueryVersion string  `json:"osquery_version"`
    TotalRAM       uint64  `json:"total_ram"`
    CPUInfo        string  `json:"cpu_info"`
    CPUCores       int     `json:"cpu_cores"`
    CPUUsage       float64 `json:"cpu_usage"`
    MACAddress     string  `json:"mac_address"`
    SerialNumber   string  `json:"serial_number"`
    HardwareModel  string  `json:"hardware_model"`
    Manufacturer   string  `json:"manufacturer"`
}
```

### 2. Hardware Detection Functions

#### Serial Number Detection
```go
func getHardwareSerialNumber() string
```

#### Platform-Specific Implementation
```go
func getHardwareSerialNumber() string {
    var cmd *exec.Cmd
    switch runtime.GOOS {
    case "windows":
        cmd = exec.Command("wmic", "bios", "get", "serialnumber")
    case "linux":
        // Linux implementation commented out (see file for details)
        return ""
    case "darwin":
        cmd = exec.Command("system_profiler", "SPHardwareDataType", "SPSerialNumberType")
    default:
        return ""
    }
    
    output, err := cmd.Output()
    if err != nil {
        return ""
    }
    
    // Clean up output
    serial := strings.TrimSpace(string(output))
    serial = strings.ReplaceAll(serial, "\n", "")
    serial = strings.ReplaceAll(serial, "\r", "")
    
    return serial
}
```

#### Hardware Model Detection
```go
func getHardwareModel() string
```

#### Manufacturer Detection
```go
func getHardwareManufacturer() string
```

### 3. Agent Service Implementation

#### Service Structure
```go
type AgentService struct {
    client *http.Client
}
```

#### Constructor
```go
func NewAgentService() *AgentService {
    return &AgentService{
        client: &http.Client{Timeout: 10 * time.Second},
    }
}
```

### 4. Agent Information Management

#### Update Agent Info
```go
func (s *AgentService) UpdateAgentInfo(ctx context.Context, cfg *config.Config, sysInfo *osinfo.SystemInfo) error
```

#### Implementation Details

`UpdateAgentInfo` builds an `AgentUpdatePayload` from the collected
`SystemInfo` and sends it as `{"payload": ...}` to the
`agent_enqueue_inventory` RPC through `rpcutil.PostEnqueue`, bounded by a
60-second timeout. The client strips NUL characters (which Postgres rejects)
from the body.

`PostEnqueue` applies the shared enqueue retry policy:

| Outcome | Behaviour |
|---|---|
| 2xx | success (an unparseable success body is only logged, never resent) |
| 401 / expired JWT | returned, so the caller's `DoWithAuthRetry` recovers the session |
| other 4xx | logged and dropped (the server rejected the payload) |
| 5xx / network error | exponential backoff with jitter (1 s → 5 min), retried until the context ends |

The scheduler wraps the call in `auth.Service.DoWithAuthRetry`.

## Integration Points

### Module Dependencies
```go
import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os/exec"
    "runtime"
    "strings"
    "time"
    
    "sentinelgo/internal/config"
    "sentinelgo/internal/osinfo"
)
```

### Usage in Main Module
```go
// Initialize services
authSvc := authservice.NewService(cfg.SupabaseURL)
agentSvc := authservice.NewAgentService()

// Agent registration
loginResp, err := authSvc.Login(ctx, cfg)
if err != nil {
    return fmt.Errorf("login failed: %w", err)
}

// Update agent information
sysInfo := osinfo.Collect()
err = agentSvc.UpdateAgentInfo(ctx, cfg, sysInfo)
if err != nil {
    return fmt.Errorf("update agent info: %w", err)
}
```

## Error Handling

### Authentication Errors
- **Missing Credentials**: Agent UUID/secret not configured
- **Invalid Credentials**: Authentication failed
- **Network Errors**: Connection issues with Supabase
- **Token Errors**: Invalid or expired tokens

### Agent Management Errors
- **Update Failures**: Database update errors
- **Hardware Detection**: Platform-specific command failures
- **Permission Issues**: Insufficient permissions for hardware queries

### Error Wrapping Strategy
```go
return fmt.Errorf("marshal request: %w", err)
return fmt.Errorf("http request: %w", err)
return fmt.Errorf("login failed: %w", err)
```

## Security Considerations

### Credential Management
- **No Hardcoded Secrets**: Credentials loaded from configuration
- **Secure Transmission**: All communication over HTTPS
- **Token Storage**: JWT tokens stored securely in config
- **Timeout Protection**: Prevents hanging connections

### Hardware Detection Security
- **Command Injection**: Uses fixed command arguments
- **Output Sanitization**: Cleans command output
- **Error Handling**: Graceful handling of command failures
- **Permission Requirements**: Minimal permissions needed

## Performance Considerations

### HTTP Client Optimization
- **Connection Reuse**: HTTP client reuse for multiple requests
- **Timeout Management**: Appropriate timeouts for all operations
- **Retry Logic**: Exponential backoff for transient failures
- **Context Awareness**: Proper cancellation support

### Hardware Detection Efficiency
- **Cached Results**: Hardware info doesn't change frequently
- **Minimal Commands**: Only necessary system commands executed
- **Error Tolerance**: Failures don't stop overall operation
- **Platform Optimization**: Efficient commands per platform

## Testing

### Authentication Service Tests
```go
func TestLogin(t *testing.T) {
    // Mock HTTP server
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/functions/v1/agent-login" {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusOK)
            w.Write([]byte(`{
                "success": true,
                "access_token": "test_token",
                "refresh_token": "test_refresh",
                "expires_in": 3600,
                "agent": {"id": "123", "agent_uuid": "test-uuid", "status": "active"}
            }`))
        }
    }))
    defer server.Close()
    
    service := NewService(server.URL)
    cfg := &config.Config{
        AgentID:    "test-uuid",
        AgentSecret: "test-secret",
    }
    
    resp, err := service.Login(context.Background(), cfg)
    assert.NoError(t, err)
    assert.True(t, resp.Success)
    assert.Equal(t, "test_token", resp.AccessToken)
}
```

### Agent Service Tests
```go
func TestUpdateAgentInfo(t *testing.T) {
    // Mock HTTP server for agent update
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "PATCH" && strings.Contains(r.URL.Path, "/rest/v1/agents") {
            w.WriteHeader(http.StatusNoContent)
        }
    }))
    defer server.Close()
    
    service := NewAgentService()
    cfg := &config.Config{
        SupabaseURL:  server.URL,
        AgentID:    "test-uuid",
        AccessToken:  "test_token",
        SupabaseKey:  "test_key",
    }
    
    sysInfo := &osinfo.SystemInfo{
        Hostname: "test-host",
        OS:       "linux",
        // ... other fields
    }
    
    err := service.UpdateAgentInfo(context.Background(), cfg, sysInfo)
    assert.NoError(t, err)
}
```

## Future Enhancements

### Planned Features

#### 1. Enhanced Authentication
```go
type EnhancedLoginRequest struct {
    AgentID      string            `json:"agent_uuid"`
    AgentSecret  string            `json:"agent_secret"`
    ClientInfo   map[string]string `json:"client_info"`
    Capabilities []string          `json:"capabilities"`
}

type EnhancedLoginResponse struct {
    LoginResponse
    Permissions []string          `json:"permissions"`
    Features    map[string]bool   `json:"features"`
    Settings    map[string]interface{} `json:"settings"`
}
```

#### 2. Advanced Hardware Detection
```go
type DetailedHardwareInfo struct {
    SerialNumber   string            `json:"serial_number"`
    Model          string            `json:"model"`
    Manufacturer   string            `json:"manufacturer"`
    UUID           string            `json:"uuid"`
    BIOS           BIOSInfo          `json:"bios"`
    Motherboard    MotherboardInfo   `json:"motherboard"`
    Processors     []ProcessorInfo   `json:"processors"`
    MemoryModules  []MemoryModule    `json:"memory_modules"`
    StorageDevices []StorageDevice   `json:"storage_devices"`
    NetworkCards   []NetworkCard     `json:"network_cards"`
    GPUs           []GPUInfo         `json:"gpus"`
}
```

#### 3. Agent Health Monitoring
```go
type HealthStatus struct {
    Status           string                 `json:"status"`
    LastSeen         time.Time             `json:"last_seen"`
    Version          string                `json:"version"`
    Uptime          time.Duration         `json:"uptime"`
    ResourceUsage    ResourceUsage        `json:"resource_usage"`
    ErrorCount       int64                `json:"error_count"`
    LastError       string                `json:"last_error"`
    Capabilities    map[string]bool       `json:"capabilities"`
    Configuration   map[string]interface{} `json:"configuration"`
}
```

#### 4. Configuration Management
```go
type ConfigurationManager struct {
    service *AgentService
    cfg     *config.Config
}

func (cm *ConfigurationManager) UpdateConfiguration(ctx context.Context, updates map[string]interface{}) error
func (cm *ConfigurationManager) GetConfiguration(ctx context.Context) (map[string]interface{}, error)
func (cm *ConfigurationManager) ValidateConfiguration(config map[string]interface{}) error
```

#### 5. Enhanced Error Handling
```go
type ServiceError struct {
    Code        string    `json:"code"`
    Message     string    `json:"message"`
    Details     string    `json:"details"`
    Timestamp   time.Time `json:"timestamp"`
    RequestID   string    `json:"request_id"`
    Retryable   bool      `json:"retryable"`
    Cause       error     `json:"-"`
}

func (e *ServiceError) Error() string {
    return fmt.Sprintf("[%s] %s: %s", e.Code, e.Message, e.Details)
}

func (e *ServiceError) Unwrap() error {
    return e.Cause
}
```

## Troubleshooting

### Common Issues

#### 1. Authentication Failures
```
Error: agent UUID and secret must be configured
```
**Solution**: Configure agent credentials in configuration file

#### 2. Network Connectivity
```
Error: http request: connection refused
```
**Solution**: Check network connectivity and Supabase URL

#### 3. Token Expiration
```
Error: refresh failed: status 401
```
**Solution**: Refresh tokens expired, require re-authentication

#### 4. Hardware Detection Failures
```
Warning: Failed to get hardware serial number
```
**Solution**: Check system permissions and platform compatibility

### Debug Commands
```bash
# Show version and running processes
./sentinelgo -version
./sentinelgo -status

# Inspect a parsed config
./sentinelgo -config /path/to/config.json -run   # foreground mode (does not daemonize)

# Tail logs on Linux / macOS
journalctl -u sentinelgo -f
tail -f /var/log/sentinelgo/agent.log

# Event log on Windows
Get-EventLog -LogName Application -Source SentinelGo -Newest 50
```

## Best Practices

### Development Guidelines
- **Error Context**: Provide clear error context with wrapping
- **Retry Logic**: Implement exponential backoff for transient failures
- **Security**: Never log sensitive authentication data
- **Timeouts**: Set appropriate timeouts for all network operations

### Operational Guidelines
- **Monitoring**: Monitor authentication success/failure rates
- **Alerting**: Alert on consecutive authentication failures
- **Rotation**: Regularly rotate agent secrets and tokens
- **Auditing**: Log authentication attempts for security auditing
