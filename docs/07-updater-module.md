# Updater Module Documentation

> **Canonical reference:** the architecture, release flow, and
> how the updater fits into the agent's runtime are in
> [`docs/08-project-overview.md`](08-project-overview.md). The
> config knobs it reads (`auto_update`, `auto_update_interval`,
> `github_owner`, `github_repo`, `current_version`) are documented
> in [`docs/02-config-module.md`](02-config-module.md). The release
> pipeline is in [`RELEASE_PROCESS.md`](../RELEASE_PROCESS.md).
>
> The on-page text below is the historical, in-depth reference for
> `internal/updater/`. It has surgical corrections for the real
> package layout, the real `Config` fields, and the canonical owner
> / repo names, but is otherwise the original deep-dive.

## Overview

The updater module (`internal/updater/`) provides automatic update
functionality for SentinelGo: GitHub release detection, binary
download, atomic binary replace, and graceful service restart. It
runs as a background goroutine started by `MainIntegration.Start()`
and respects the `auto_update` and `auto_update_interval` config
knobs (see [`docs/02`](02-config-module.md)).

## Architecture

```
┌─────────────────────────────────────────┐
│           Updater Module              │
│     (internal/updater/updater.go)      │
├─────────────────────────────────────────┤
│ • GitHub Release Detection            │
│ • Binary Download & Replacement       │
│ • Process Management                 │
│ • Cross-Platform Service Integration  │
│ • Version Management                 │
│ • Auto-Update Scheduling             │
│ • Startup Update Check               │
│ • Internet Connectivity Check        │
└─────────────────────────────────────────┘
```

## Core Components

### 1. Data Structures

#### GitHub Release Information
```go
type GitHubRelease struct {
    TagName string  `json:"tag_name"`
    Assets  []Asset `json:"assets"`
}

type Asset struct {
    Name string `json:"name"`
    URL  string `json:"browser_download_url"`
}
```

#### Process Information
```go
type ProcessInfo struct {
    PID     int
    Version string
    CmdLine string
}
```

### 2. Main Update Function

#### CheckAndApply Function
```go
func CheckAndApply(ctx context.Context, cfg *config.Config) error
```

#### Update Process Flow
```go
func CheckAndApply(ctx context.Context, cfg *config.Config) error {
    // 1. Fetch latest release from GitHub
    latest, err := fetchLatestRelease(ctx, cfg)
    if err != nil {
        return fmt.Errorf("fetch latest release: %w", err)
    }
    
    // 2. Check if update is needed
    if latest.TagName == cfg.CurrentVersion {
        fmt.Printf("Already up to date: %s\n", latest.TagName)
        return nil // already up-to-date
    }
    
    // 3. Select appropriate asset for platform
    assetURL, err := selectAsset(latest, runtime.GOOS, runtime.GOARCH)
    if err != nil {
        return fmt.Errorf("select asset: %w", err)
    }
    
    fmt.Printf("Found update: %s -> %s\n", cfg.CurrentVersion, latest.TagName)
    
    // 4. Stop old processes
    fmt.Println("Stopping old SentinelGo processes before update...")
    if err := stopOldProcesses(); err != nil {
        fmt.Printf("Warning: Failed to stop some old processes: %v\n", err)
    }
    
    // 5. Wait for processes to terminate
    fmt.Println("Waiting for old processes to fully terminate...")
    time.Sleep(5 * time.Second)
    
    // 6. Force kill remaining processes
    processes, _ := findOldProcesses()
    if len(processes) > 0 {
        fmt.Printf("Warning: %d old process(es) still running, proceeding anyway...\n", len(processes))
        // Force kill implementation
    }
    
    // 7. Download and replace binary
    newPath, err := downloadAndReplace(ctx, assetURL, latest.TagName)
    if err != nil {
        return fmt.Errorf("download and replace: %w", err)
    }
    
    // 8. Verify binary replacement
    if _, err := os.Stat(newPath); os.IsNotExist(err) {
        return fmt.Errorf("new binary not found after replacement: %w", err)
    }
    
    fmt.Printf("Successfully updated to version %s\n", latest.TagName)
    
    // 9. Update configuration
    cfg.CurrentVersion = latest.TagName
    if err := cfg.Save(); err != nil {
        return fmt.Errorf("save config: %w", err)
    }
    
    // 10. Restart with new binary
    return restart(newPath)
}
```

### 3. GitHub Release Detection

#### Fetch Latest Release
```go
func fetchLatestRelease(ctx context.Context, cfg *config.Config) (*GitHubRelease, error)
```

#### Implementation Details
```go
func fetchLatestRelease(ctx context.Context, cfg *config.Config) (*GitHubRelease, error) {
    url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", cfg.GitHubOwner, cfg.GitHubRepo)
    fmt.Printf("Fetching release from: %s\n", url)
    
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return nil, err
    }
    req.Header.Set("Accept", "application/vnd.github.v3+json")
    
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("GitHub API status %d", resp.StatusCode)
    }
    
    var rel GitHubRelease
    if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
        return nil, err
    }
    
    fmt.Printf("Fetched release: %s with %d assets\n", rel.TagName, len(rel.Assets))
    return &rel, nil
}
```

### 4. Asset Selection

#### Platform-Specific Asset Selection
```go
func selectAsset(rel *GitHubRelease, goos, goarch string) (string, error)
```

#### Asset Naming Convention
```go
func selectAsset(rel *GitHubRelease, goos, goarch string) (string, error) {
    var suffix string
    switch goos {
    case "windows":
        suffix = ".exe"
    case "linux", "darwin":
        suffix = ""
    default:
        return "", fmt.Errorf("unsupported OS %s", goos)
    }
    
    pattern := fmt.Sprintf("sentinelgo-%s-%s%s", goos, goarch, suffix)
    fmt.Printf("Looking for asset: %s\n", pattern)
    
    for _, asset := range rel.Assets {
        if asset.Name == pattern {
            fmt.Printf("Found matching asset: %s\n", asset.Name)
            return asset.URL, nil
        }
    }
    
    return "", fmt.Errorf("no matching asset for %s-%s", goos, goarch)
}
```

#### Expected Asset Names
- **Linux AMD64**: `sentinelgo-linux-amd64`
- **Linux ARM64**: `sentinelgo-linux-arm64`
- **macOS AMD64**: `sentinelgo-darwin-amd64`
- **macOS ARM64**: `sentinelgo-darwin-arm64`
- **Windows AMD64**: `sentinelgo-windows-amd64.exe`
- **Windows ARM64**: `sentinelgo-windows-arm64.exe`

### 5. Process Management

#### Find Old Processes
```go
func findOldProcesses() ([]ProcessInfo, error)
```

#### Cross-Platform Process Detection
```go
func findOldProcesses() ([]ProcessInfo, error) {
    var cmd *exec.Cmd
    
    switch runtime.GOOS {
    case "windows":
        cmd = exec.Command("tasklist", "/fi", "imagename eq sentinelgo.exe", "/fo", "csv", "/v")
    case "linux", "darwin":
        cmd = exec.Command("ps", "aux")
    default:
        return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
    }
    
    output, err := cmd.Output()
    if err != nil {
        return nil, err
    }
    
    return parseProcessOutput(string(output)), nil
}
```

#### Process Output Parsing
```go
func parseProcessOutput(output string) []ProcessInfo {
    var processes []ProcessInfo
    lines := strings.Split(output, "\n")
    
    currentPID := os.Getpid()
    currentVersion := getCurrentVersion()
    
    for _, line := range lines {
        if strings.TrimSpace(line) == "" {
            continue
        }
        
        var info ProcessInfo
        
        switch runtime.GOOS {
        case "windows":
            if strings.Contains(line, "sentinelgo.exe") {
                fields := strings.Split(line, ",")
                if len(fields) >= 5 {
                    pid, _ := strconv.Atoi(strings.Trim(fields[1], `"`))
                    if pid != currentPID { // Skip current process
                        info.PID = pid
                        info.CmdLine = strings.Trim(fields[8], `"`)
                        info.Version = getProcessVersion(info.CmdLine, pid)
                        if info.Version != currentVersion {
                            processes = append(processes, info)
                        }
                    }
                }
            }
        case "linux", "darwin":
            if strings.Contains(line, "sentinelgo") && !strings.Contains(line, "grep") && 
               !strings.Contains(line, "systemctl") && !strings.Contains(line, "journalctl") && 
               !strings.Contains(line, "editor") {
                fields := strings.Fields(line)
                if len(fields) >= 2 {
                    pid, _ := strconv.Atoi(fields[1])
                    if pid != currentPID { // Skip current process
                        info.PID = pid
                        info.CmdLine = strings.Join(fields[10:], " ")
                        info.Version = getProcessVersion(info.CmdLine, pid)
                        if info.Version != currentVersion {
                            processes = append(processes, info)
                        }
                    }
                }
            }
        }
    }
    
    return processes
}
```

### 6. Version Detection

#### Process Version Detection
```go
func getProcessVersion(cmdLine string, pid int) string
```

#### Multi-Method Version Detection
```go
func getProcessVersion(cmdLine string, pid int) string {
    // 1. Try to extract version from command line
    if version := extractVersionFromCmd(cmdLine); version != "unknown" {
        return version
    }
    
    // 2. Try to get version from binary
    if version := getBinaryVersion(cmdLine); version != "unknown" {
        return version
    }
    
    // 3. Try to get version from executable path
    if version := extractVersionFromPath(cmdLine); version != "unknown" {
        return version
    }
    
    return "unknown"
}
```

#### Version Extraction Methods
```go
// From command line arguments
func extractVersionFromCmd(cmdLine string) string {
    if strings.Contains(cmdLine, "-version=") {
        parts := strings.Split(cmdLine, "-version=")
        if len(parts) > 1 {
            version := strings.Split(parts[1], " ")[0]
            return strings.Trim(version, `"`)
        }
    }
    
    if strings.Contains(cmdLine, "-version") || strings.Contains(cmdLine, "--version") {
        parts := strings.Fields(cmdLine)
        for i, part := range parts {
            if (part == "-version" || part == "--version") && i+1 < len(parts) {
                return strings.Trim(parts[i+1], `"`)
            }
        }
    }
    
    return "unknown"
}

// From binary execution
func getBinaryVersion(cmdLine string) string {
    var binaryPath string
    parts := strings.Fields(cmdLine)
    
    if len(parts) > 0 {
        binaryPath = parts[0]
        if !strings.Contains(binaryPath, "/") && runtime.GOOS != "windows" {
            if path, err := exec.LookPath(binaryPath); err == nil {
                binaryPath = path
            }
        }
    }
    
    if binaryPath != "" {
        cmd := exec.Command(binaryPath, "-version")
        output, err := cmd.Output()
        if err == nil {
            outputStr := string(output)
            lines := strings.Split(outputStr, "\n")
            for _, line := range lines {
                if strings.Contains(line, "version:") || strings.Contains(line, "version") {
                    parts := strings.Fields(line)
                    for i, part := range parts {
                        if strings.Contains(part, "version") && i+1 < len(parts) {
                            return strings.Trim(parts[i+1], ",")
                        }
                    }
                }
            }
        }
    }
    
    return "unknown"
}

// From executable path
func extractVersionFromPath(path string) string {
    parts := strings.Split(path, "-")
    for i := len(parts) - 1; i >= 0; i-- {
        if strings.HasPrefix(parts[i], "v") {
            return strings.Trim(parts[i], `"`)
        }
    }
    return "unknown"
}
```

### 7. Process Termination

#### Stop Old Processes
```go
func stopOldProcesses() error
```

#### Graceful and Force Termination
```go
func stopOldProcesses() error {
    processes, err := findOldProcesses()
    if err != nil {
        return err
    }
    
    if len(processes) == 0 {
        fmt.Println("No old SentinelGo processes found")
        return nil
    }
    
    fmt.Printf("Found %d old SentinelGo process(es) to stop:\n", len(processes))
    for _, proc := range processes {
        fmt.Printf("  PID: %d, Version: %s\n", proc.PID, proc.Version)
    }
    
    fmt.Println("Stopping old processes...")
    for _, proc := range processes {
        var cmd *exec.Cmd
        switch runtime.GOOS {
        case "windows":
            cmd = exec.Command("taskkill", "/F", "/PID", strconv.Itoa(proc.PID))
        case "linux", "darwin":
            cmd = exec.Command("kill", "-TERM", strconv.Itoa(proc.PID))
        }
        
        if err := cmd.Run(); err != nil {
            fmt.Printf("Failed to stop PID %d: %v\n", proc.PID, err)
        } else {
            fmt.Printf("Stopped PID %d\n", proc.PID)
        }
    }
    
    // Wait for graceful termination
    time.Sleep(3 * time.Second)
    
    // Force kill remaining processes
    remaining, _ := findOldProcesses()
    if len(remaining) > 0 {
        fmt.Printf("Force killing %d remaining process(es)...\n", len(remaining))
        for _, proc := range remaining {
            var cmd *exec.Cmd
            switch runtime.GOOS {
            case "windows":
                cmd = exec.Command("taskkill", "/F", "/PID", strconv.Itoa(proc.PID))
            case "linux", "darwin":
                cmd = exec.Command("kill", "-KILL", strconv.Itoa(proc.PID))
            }
            if err := cmd.Run(); err != nil {
                fmt.Printf("Warning: failed to force kill PID %d: %v\n", proc.PID, err)
            }
        }
        time.Sleep(2 * time.Second)
    }
    
    return nil
}
```

### 8. Binary Download and Replacement

#### Download and Replace
```go
func downloadAndReplace(ctx context.Context, url, version string) (string, error)
```

#### Download Implementation
```go
func downloadAndReplace(ctx context.Context, url, version string) (string, error) {
    req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
    if err != nil {
        return "", err
    }
    
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()
    
    if resp.StatusCode != http.StatusOK {
        return "", fmt.Errorf("download failed status %d", resp.StatusCode)
    }
    
    selfPath, err := os.Executable()
    if err != nil {
        return "", err
    }
    
    newPath := selfPath + ".new"
    f, err := os.OpenFile(newPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
    if err != nil {
        return "", err
    }
    defer f.Close()
    
    if _, err := io.Copy(f, resp.Body); err != nil {
        return "", err
    }
    
    return newPath, nil
}
```

### 9. Application Restart

#### Cross-Platform Restart
```go
func restart(newPath string) error
```

#### Platform-Specific Restart Logic
```go
func restart(newPath string) error {
    selfPath, err := os.Executable()
    if err != nil {
        return err
    }
    
    // macOS: Special handling for launchd services
    if runtime.GOOS == "darwin" {
        return restartMacOS(newPath, selfPath)
    }
    
    // Linux and Windows
    if runtime.GOOS != "windows" {
        // Replace current binary with new one
        if err := os.Rename(newPath, selfPath); err != nil {
            return err
        }
        time.Sleep(2 * time.Second)
        cmd := exec.Command(selfPath)
        return cmd.Start()
    } else {
        // Windows: Use batch script for replacement after exit
        return restartWindows(newPath, selfPath)
    }
}

func restartMacOS(newPath, selfPath string) error {
    // Stop launchd service
    if err := stopLaunchdService(); err != nil {
        fmt.Printf("Warning: Failed to stop launchd service: %v\n", err)
    }
    time.Sleep(3 * time.Second)
    
    // Replace binary
    if err := os.Rename(newPath, selfPath); err != nil {
        return fmt.Errorf("failed to replace binary: %w", err)
    }
    
    // Verify replacement
    if _, err := os.Stat(selfPath); os.IsNotExist(err) {
        return fmt.Errorf("new binary not found after replacement: %w", err)
    }
    
    fmt.Printf("Successfully updated to version %s\n", extractVersionFromPath(newPath))
    time.Sleep(2 * time.Second)
    
    // Start launchd service
    if err := startLaunchdService(); err != nil {
        fmt.Printf("Warning: Failed to start launchd service: %v\n", err)
        fmt.Println("Falling back to direct execution...")
        cmd := exec.Command(selfPath, "-run")
        if err := cmd.Start(); err != nil {
            return fmt.Errorf("failed to start fallback execution: %w", err)
        }
        fmt.Println("Started SentinelGo in direct execution mode")
        return nil
    }
    
    return nil
}

func restartWindows(newPath, selfPath string) error {
    bat := selfPath + ".bat"
    script := fmt.Sprintf(`@echo off

timeout /t 2 /nobreak >nul
move /Y "%s" "%s"
"%s"
del "%s"`, newPath, selfPath, selfPath, bat)
    
    if err := os.WriteFile(bat, []byte(script), 0644); err != nil {
        return err
    }
    
    cmd := exec.Command(bat)
    return cmd.Start()
}
```

### 10. Auto-Update Scheduler

#### Background Update Checker
```go
func AutoUpdateChecker(ctx context.Context, cfg *config.Config)
```

#### Scheduling Implementation
```go
func AutoUpdateChecker(ctx context.Context, cfg *config.Config) {
    ticker := time.NewTicker(1 * time.Hour) // Check every hour
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            fmt.Println("Checking for updates...")

            if err := CheckAndApply(ctx, cfg); err != nil {
                fmt.Printf("Auto-update failed: %v\n", err)
            } else {
                fmt.Println("Auto-update completed successfully")
            }
        }
    }
}
```

### 11. Startup Update Check

#### Internet Connectivity Check
```go
func CheckInternetConnectivity() bool
```

#### Implementation Details
```go
func CheckInternetConnectivity() bool {
    // Try to connect to multiple reliable endpoints
    endpoints := []string{
        "api.github.com:443",
        "google.com:443",
        "cloudflare.com:443",
    }

    for _, endpoint := range endpoints {
        timeout := 5 * time.Second
        conn, err := net.DialTimeout("tcp", endpoint, timeout)
        if err == nil {
            conn.Close()
            log.Printf("Internet connectivity confirmed via %s", endpoint)
            return true
        }
    }

    log.Printf("No internet connectivity detected")
    return false
}
```

#### HTTP-Based Connectivity Check
```go
func CheckInternetWithHTTP() bool
```

#### Startup Update Check Function
```go
func StartupUpdateCheck(ctx context.Context, cfg *config.Config, token string) error
```

#### Startup Update Flow
```go
func StartupUpdateCheck(ctx context.Context, cfg *config.Config, token string) error {
    log.Println("Performing startup update check...")

    // Check internet connectivity via TCP
    if !CheckInternetConnectivity() {
        log.Println("No internet connection on startup, skipping update check")
        return nil
    }

    // Additional HTTP-based check for more reliable detection
    if !CheckInternetWithHTTP() {
        log.Println("HTTP connectivity check failed on startup, skipping update check")
        return nil
    }

    log.Println("Internet connection confirmed, checking for updates...")

    // Attempt update with retry
    if err := CheckAndApplyWithRetry(ctx, cfg, token); err != nil {
        log.Printf("Startup update check failed: %v", err)
        return fmt.Errorf("startup update check failed: %w", err)
    }

    log.Println("Startup update check completed successfully")
    return nil
}
```

#### Integration in Main Startup
```go
// In internal/main_integration.go Start() method
if mi.cfg.AutoUpdate {
    log.Println("Auto-update is enabled, performing startup update check...")
    go func() {
        if err := updater.StartupUpdateCheck(ctx, mi.cfg, ""); err != nil {
            log.Printf("Startup update check failed: %v", err)
        }
    }()
}
```

## Integration Points

### Module Dependencies
```go
import (
    "context"
    "encoding/json"
    "fmt"
    "net"
    "io"
    "net/http"
    "os"
    "os/exec"
    "runtime"
    "strconv"
"strings"
    "time"
    
    "sentinelgo/internal/config"
)
```
up update check (runs on application boot)
ifmi.cfg.AutoUpdte {
    log.Println("Ae is nabled, perfomingstartup update check...")
    go func() {
         err:= updatr.StartupUpdateCheck(ctx, mi.cfg, ""); err != nil {
            log.Printf("Startup update check failed: %v", err)
        }
    }()
}

// Start auto-updater if eed (background prioic checks)
### Usage in Main Module
```go
// Start auto-updater if enabled
if p.cfg.AutoUpdate {
    go updater.AutoUpdateChecker(ctx, p.cfg)
}

// Manual update check
if err := updater.CheckAndApply(ctx, p.cfg); err != nil {
    logger.Errorf("Update check failed: %v", err)
}
```

## Error Handling

### Update Error Types
1. **Network Errors**: GitHub API or download failures
2. **Process Errors**: Failed to stop/start processes
3. **File System Errors**: Permission issues, disk space
4. **Version Errors**: Version parsing or comparison failures
5. **Service Errors**: Launchd/systemd integration failures

### Error Recovery
- **Graceful Degradation**: Continue operation if update fails
- **Retry Logic**: Built-in retry for transient failures
- **Fallback Options**: Alternative restart methods
- **Cleanup**: Proper cleanup of temporary files

## Security Considerations

### Binary Security
- **HTTPS Downloads**: All downloads over HTTPS
- **Signature Verification**: Future enhancement for binary signatures
- **Permission Checks**: Verify file permissions before replacement
- **Atomic Operations**: Ensure atomic binary replacement

### Process Security
- **Privilege Escalation**: Avoid unnecessary privilege escalation
- **Signal Handling**: Proper signal handling for termination
- **Resource Cleanup**: Clean up temporary files and processes
- **Service Security**: Maintain service security context

## Performance Considerations

### Download Efficiency
- **Streaming Downloads**: Stream large binaries to disk
- **Progress Reporting**: Provide download progress feedback
- **Resume Capability**: Future enhancement for interrupted downloads
- **Bandwidth Limiting**: Consider bandwidth constraints

### Process Management
- **Minimal Downtime**: Quick process transitions
- **Resource Cleanup**: Efficient resource management
- **Parallel Operations**: Where safe and beneficial
- **Memory Efficiency**: Minimal memory footprint during updates

## Testing

### Update Process Testing
```go
func TestUpdateProcess(t *testing.T) {
    // Mock GitHub API
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if strings.Contains(r.URL.Path, "/releases/latest") {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusOK)
            w.Write([]byte(`{
                "tag_name": "v2.0.0",
                "assets": [
                    {
                        "name": "sentinelgo-linux-amd64",
                        "browser_download_url": "http://example.com/sentinelgo-linux-amd64"
                    }
                ]
            }`))
        }
    }))
    defer server.Close()
    
    // Mock binary download
    downloadServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("mock binary content"))
    }))
    defer downloadServer.Close()
    
    cfg := &config.Config{
        GitHubOwner:    "test",
        GitHubRepo:     "test",
        CurrentVersion: "v1.0.0",
    }
    
    // Test update process (mocked)
    err := CheckAndApply(context.Background(), cfg)
    // Assertions based on mocked behavior
}
```

## Future Enhancements

### Planned Features

#### 1. Binary Signature Verification
```go
func verifyBinarySignature(binaryPath string, signatureURL string) error {
    // Download signature
    sigResp, err := http.Get(signatureURL)
    if err != nil {
        return err
    }
    defer sigResp.Body.Close()
    
    signature, err := io.ReadAll(sigResp.Body)
    if err != nil {
        return err
    }
    
    // Verify binary signature
    return verifySignature(binaryPath, signature)
}
```

#### 2. Delta Updates
```go
type DeltaUpdate struct {
    FromVersion string `json:"from_version"`
    ToVersion   string `json:"to_version"`
    DeltaURL    string `json:"delta_url"`
    DeltaHash   string `json:"delta_hash"`
}

func applyDeltaUpdate(currentBinary, deltaBinary string) error {
    // Apply binary delta to current binary
    return nil
}
```

#### 3. Rollback Capability
```go
type RollbackManager struct {
    backupDir string
    maxRollbacks int
}

func (rm *RollbackManager) CreateBackup(binaryPath string) error
func (rm *RollbackManager) Rollback(targetVersion string) error
func (rm *RollbackManager) ListRollbacks() []string
```

#### 4. Update Scheduling
```go
type UpdateScheduler struct {
    schedule     time.Time
    window       time.Duration
    maxRetries   int
    autoApprove  bool
}

func (us *UpdateScheduler) ScheduleUpdate(updateTime time.Time) error
func (us *UpdateScheduler) ShouldUpdateNow() bool
```

#### 5. Enhanced Progress Reporting
```go
type UpdateProgress struct {
    Stage        string  `json:"stage"`
    Progress     float64 `json:"progress"`
    TotalBytes   int64   `json:"total_bytes"`
    Downloaded   int64   `json:"downloaded"`
    Speed        int64   `json:"speed"`
    ETA          int64   `json:"eta"`
}

type ProgressReporter interface {
    ReportProgress(progress UpdateProgress)
}
```

## Troubleshooting

### Common Issues

#### 1. Update Download Failures
```
Error: download failed status 404
```
**Solution**: Check GitHub repository and asset availability

#### 2. Process Termination Issues
```
Warning: Failed to stop PID 1234
```
**Solution**: Check process permissions and user rights

#### 3. Binary Replacement Failures
```
Error: failed to replace binary: permission denied
```
**Solution**: Check file permissions and run with appropriate privileges

#### 4. Service Integration Issues
```
Error: failed to start launchd service
```
**Solution**: Check launchd configuration and system permissions

### Debug Commands
```bash
# Check current version
./sentinelgo -version

# Force update check
./sentinelgo -run  # Will trigger update check

# Check GitHub releases
curl https://api.github.com/repos/<github_owner>/SentinelGo/releases/latest

# Verify binary integrity
file /opt/sentinelgo/sentinelgo
ls -la /opt/sentinelgo/
```

## Best Practices

### Development Guidelines
- **Atomic Updates**: Ensure updates are atomic and reversible
- **Error Recovery**: Handle all failure modes gracefully
- **Security**: Verify binary integrity before replacement
- **Testing**: Test update process thoroughly

### Operational Guidelines
- **Backup Strategy**: Maintain backup of previous versions
- **Monitoring**: Monitor update success/failure rates
- **Alerting**: Alert on update failures
- **Documentation**: Document update procedures and troubleshooting
