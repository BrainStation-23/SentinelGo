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

The service module (`internal/service/`) provides authentication and
agent management functionality for SentinelGo. It consists of two
main components:

- `internal/service/auth/` — JWT-based authentication with Supabase
  (login, refresh, circuit breaker, keychain persistence).
- `internal/service/agent/` — periodic agent-info upload (calls
  `osinfo.Collect()`, posts to the `agent-info` Edge Function).

## Architecture

```
┌─────────────────────────────────────────┐
│           Service Module               │
│       (internal/service/)             │
├─────────────────────────────────────────┤
│ ┌─────────────────┐ ┌─────────────┐ │
│ │  authService.go │ │agentService│ │ │
│ │                 │ │    .go     │ │ │
│ │ • JWT Auth      │ │ • Agent    │ │ │
│ │ • Login/Refresh │ │   Mgmt     │ │ │
│ │ • Token Mgmt    │ │ • Hardware │ │ │
│ │ • API Comm      │ │   Detection│ │ │
│ └─────────────────┘ └─────────────┘ │
└─────────────────────────────────────────┘
```

## Authentication Service (authService.go)

### 1. Core Data Structures

#### Login Request/Response
```go
type LoginRequest struct {
    AgentID     string `json:"agent_uuid"`
    AgentSecret string `json:"agent_secret"`
}

type LoginResponse struct {
    Success      bool   `json:"success"`
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int    `json:"expires_in"`
    Agent        Agent  `json:"agent"`
}

type Agent struct {
    ID        string `json:"id"`
    AgentID   string `json:"agent_uuid"`
    Status    string `json:"status"`
}
```

#### Token Refresh Structures
```go
type RefreshRequest struct {
    RefreshToken string `json:"refresh_token"`
}

type RefreshResponse struct {
    AccessToken  string `json:"access_token"`
    RefreshToken string `json:"refresh_token"`
    ExpiresIn    int    `json:"expires_in"`
}
```

#### Service Configuration
```go
type Service struct {
    client  *http.Client
    baseURL string
}
```

### 2. Constants and Configuration

#### Service Endpoints
```go
const (
    agentLoginEndpoint = "/functions/v1/agent-login"
    defaultTimeout     = 60 * time.Second
    maxRetries         = 3
)
```

#### Configuration Details
- **Login Endpoint**: Custom Supabase function for agent authentication
- **Timeout**: 60 seconds for authentication operations
- **Retries**: Up to 3 attempts with exponential backoff
- **Base URL**: Configurable Supabase project URL

### 3. Service Initialization

#### Constructor Function
```go
func NewService(baseURL string) *Service {
    return &Service{
        client: &http.Client{
            Timeout: defaultTimeout,
        },
        baseURL: baseURL,
    }
}
```

#### Initialization Features
- **HTTP Client**: Configured with appropriate timeout
- **Base URL**: Supabase project URL for API calls
- **Reusable**: Service instance can be reused for multiple operations

### 4. Authentication Flow

#### Login Process
```go
func (s *Service) Login(ctx context.Context, cfg *config.Config) (*LoginResponse, error)
```

#### Login Implementation
```go
func (s *Service) Login(ctx context.Context, cfg *config.Config) (*LoginResponse, error) {
    // 1. Validate credentials
    if cfg.AgentID == "" || cfg.AgentSecret == "" {
        return nil, fmt.Errorf("agent ID and secret must be configured")
    }
    
    // 2. Create request
    req := LoginRequest{
        AgentID:     cfg.AgentID,
        AgentSecret: cfg.AgentSecret,
    }
    
    reqBody, err := json.Marshal(req)
    if err != nil {
        return nil, fmt.Errorf("marshal request: %w", err)
    }
    
    // 3. Send request with retry logic
    url := cfg.SupabaseURL + agentLoginEndpoint
    var resp *LoginResponse
    var lastErr error
    
    for attempt := 0; attempt < maxRetries; attempt++ {
        if attempt > 0 {
            select {
            case <-ctx.Done():
                return nil, ctx.Err()
            case <-time.After(time.Duration(attempt) * time.Second):
            }
        }
        
        // HTTP request implementation
        httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqBody))
        if err != nil {
            lastErr = fmt.Errorf("create request: %w", err)
            continue
        }
        
        httpReq.Header.Set("Content-Type", "application/json")
        
        httpResp, err := s.client.Do(httpReq)
        if err != nil {
            lastErr = fmt.Errorf("http request: %w", err)
            continue
        }
        
        // Response processing
        body, err := io.ReadAll(httpResp.Body)
        httpResp.Body.Close()
        if err != nil {
            lastErr = fmt.Errorf("read response: %w", err)
            continue
        }
        
        if httpResp.StatusCode != http.StatusOK {
            lastErr = fmt.Errorf("login failed: status %d, body: %s", httpResp.StatusCode, string(body))
            continue
        }
        
        var loginResp LoginResponse
        if err := json.Unmarshal(body, &loginResp); err != nil {
            lastErr = fmt.Errorf("unmarshal response: %w", err)
            continue
        }
        
        resp = &loginResp
        break
    }
    
    if resp == nil {
        return nil, fmt.Errorf("login failed after %d attempts: %w", maxRetries, lastErr)
    }
    
    return resp, nil
}
```

### 5. Token Refresh

#### Refresh Process
```go
func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (*RefreshResponse, error)
```

#### Refresh Implementation
```go
func (s *Service) RefreshToken(ctx context.Context, refreshToken string) (*RefreshResponse, error) {
    if refreshToken == "" {
        return nil, fmt.Errorf("refresh token cannot be empty")
    }
    
    req := RefreshRequest{
        RefreshToken: refreshToken,
    }
    
    reqBody, err := json.Marshal(req)
    if err != nil {
        return nil, fmt.Errorf("marshal refresh request: %w", err)
    }
    
    url := s.baseURL + "/functions/v1/agent-refresh"
    var resp *RefreshResponse
    var lastErr error
    
    for attempt := 0; attempt < maxRetries; attempt++ {
        if attempt > 0 {
            select {
            case <-ctx.Done():
                return nil, ctx.Err()
            case <-time.After(time.Duration(attempt) * time.Second):
            }
        }
        
        httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqBody))
        if err != nil {
            lastErr = fmt.Errorf("create refresh request: %w", err)
            continue
        }
        
        httpReq.Header.Set("Content-Type", "application/json")
        
        httpResp, err := s.client.Do(httpReq)
        if err != nil {
            lastErr = fmt.Errorf("refresh http request: %w", err)
            continue
        }
        
        body, err := io.ReadAll(httpResp.Body)
        httpResp.Body.Close()
        if err != nil {
            lastErr = fmt.Errorf("read refresh response: %w", err)
            continue
        }
        
        if httpResp.StatusCode != http.StatusOK {
            lastErr = fmt.Errorf("refresh failed: status %d, body: %s", httpResp.StatusCode, string(body))
            continue
        }
        
        var refreshResp RefreshResponse
        if err := json.Unmarshal(body, &refreshResp); err != nil {
            lastErr = fmt.Errorf("unmarshal refresh response: %w", err)
            continue
        }
        
        resp = &refreshResp
        break
    }
    
    if resp == nil {
        return nil, fmt.Errorf("token refresh failed after %d attempts: %w", maxRetries, lastErr)
    }
    
    return resp, nil
}
```

### 6. Helper Methods

#### Agent ID Access
```go
func (lr *LoginResponse) GetAgentID() string {
    return lr.Agent.ID
}
```

#### Compatibility Method
- Provides backward compatibility for accessing agent ID
- Abstracts internal structure changes
- Simplifies calling code

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
```go
func (s *AgentService) UpdateAgentInfo(ctx context.Context, cfg *config.Config, sysInfo *osinfo.SystemInfo) error {
    // 1. Create payload with system information
    payload := AgentUpdatePayload{
        Status:         "active",
        Hostname:       sysInfo.Hostname,
        ComputerName:   sysInfo.Hostname,
        OSName:         sysInfo.OS,
        OSVersion:      sysInfo.PlatformVer,
        OSqueryVersion: "1.0.0", // TODO: Get actual osquery version
        TotalRAM:       sysInfo.Memory.Total,
        CPUInfo:        sysInfo.CPU.ModelName,
        CPUCores:       sysInfo.CPU.Cores,
        CPUUsage:       sysInfo.CPU.Usage,
        MACAddress:     sysInfo.MACAddress,
        SerialNumber:   getHardwareSerialNumber(),
        HardwareModel:  getHardwareModel(),
        Manufacturer:   getHardwareManufacturer(),
    }
    
    // 2. Marshal payload
    body, err := json.Marshal(payload)
    if err != nil {
        return fmt.Errorf("marshal agent update payload: %w", err)
    }
    
    // 3. Create HTTP request
    url := fmt.Sprintf("%s/rest/v1/agents?agent_uuid=eq.%s", cfg.SupabaseURL, cfg.AgentID)
    req, err := http.NewRequestWithContext(ctx, "PATCH", url, bytes.NewReader(body))
    if err != nil {
        return fmt.Errorf("create agent update request: %w", err)
    }
    
    // 4. Set headers
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Accept", "application/json")
    req.Header.Set("Authorization", "Bearer "+cfg.AccessToken)
    req.Header.Set("apikey", cfg.SupabaseKey)
    req.Header.Set("Prefer", "return=minimal")
    
    // 5. Send request
    resp, err := s.client.Do(req)
    if err != nil {
        return fmt.Errorf("update agent info: %w", err)
    }
    defer resp.Body.Close()
    
    // 6. Handle response
    if resp.StatusCode >= 400 {
        respBody, _ := io.ReadAll(resp.Body)
        return fmt.Errorf("agent update failed with status %d", resp.StatusCode)
    }
    
    return nil
}
```

#### Set Agent Status
```go
func (s *AgentService) SetAgentStatus(ctx context.Context, cfg *config.Config, status string) error
```

#### Get Agent Info
```go
func (s *AgentService) GetAgentInfo(ctx context.Context, cfg *config.Config) (map[string]interface{}, error)
```

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
