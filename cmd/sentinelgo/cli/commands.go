package cli

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/lockfile"
	"sentinelgo/internal/logging"
	"sentinelgo/internal/osinfo"
	"sentinelgo/internal/sanitize"
	agentsvc "sentinelgo/internal/service/agent"
	authsvc "sentinelgo/internal/service/auth"
	"sentinelgo/internal/service/rpcutil"
)

// Test seams. The handlers below load the system-wide config, exit the
// process, wait for OS signals and run the (slow, host-dependent) OS info
// collector; tests swap these out so none of that happens in-process.
var (
	loadDefaultConfig = func() (*config.Config, error) { return config.Load("") }
	osExit            = os.Exit
	logFatalf         = log.Fatalf
	notifySignals     = signal.Notify
	collectOSInfo     = osinfo.Collect
	newAgentLock      = func() *lockfile.LockFile { return lockfile.NewLockFile(lockfile.AgentLockName) }
)

// acquireAgentLock takes the agent's process lock for a CLI command that runs
// the audit-log pipeline. Run next to the service, a second pipeline on the
// same checkpoints.json and SQLite queue collected and uploaded the same logs
// again (#436), so the command refuses while the service (or -run) holds it.
func acquireAgentLock() (release func(), err error) {
	lock := newAgentLock()
	if err := lock.TryAcquire(); err != nil {
		if errors.Is(err, lockfile.ErrAlreadyRunning) {
			return nil, errors.New("the SentinelGo agent is running and already collects and uploads audit logs; stop it first")
		}
		return nil, fmt.Errorf("take the agent lock: %w", err)
	}
	return func() { _ = lock.Release() }, nil
}

func HandleAuditLogsStandalone(cfg *config.Config) {
	fmt.Println("Starting audit logs service in standalone mode...")

	release, err := acquireAgentLock()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		osExit(1)
		return
	}
	defer release()

	li, err := logging.NewLoggingIntegration(cfg)
	if err != nil {
		fmt.Printf("Failed to create logging integration: %v\n", err)
		osExit(1)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := li.Start(ctx); err != nil {
		fmt.Printf("Failed to start logging service: %v\n", err)
		osExit(1)
		return
	}

	fmt.Println("Audit logs service is running. Press Ctrl+C to stop.")
	sigChan := make(chan os.Signal, 1)
	notifySignals(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nStopping audit logs service...")
	if err := li.Stop(); err != nil {
		fmt.Printf("Warning: failed to stop logging service: %v\n", err)
	}
}

func HandleAuditLogsStatus(cfg *config.Config) {
	fmt.Println("Audit Logs Service Status")
	fmt.Println("=========================")
	fmt.Printf("Service Enabled: %v\n", cfg.GetAuditLogsEnabled())
	fmt.Printf("Device ID: %s\n", cfg.DeviceID)
	fmt.Printf("Agent Version: %s\n", cfg.CurrentVersion)
	fmt.Printf("OS Type: %s\n", runtime.GOOS)
	if v := cfg.ServerConfigVersion(); v > 0 {
		fmt.Printf("Server Config Version: %d\n", v)
	}

	switch {
	case cfg.GetAuditLogsEnabled():
		fmt.Println("\nStatus: Service is configured to run with the main agent")
	case cfg.AuditLogsDisabledByServer():
		fmt.Println("\nStatus: Service is stopped: audit logs disabled by server (console setting)")
	default:
		fmt.Println("\nStatus: Service is disabled. Enable via audit_logs_enabled in config")
	}
}

// withLoggingIntegrationForConfig is the testable core of withLoggingIntegration.
// It accepts an already-loaded config and returns an error instead of calling os.Exit.
func withLoggingIntegrationForConfig(cfg *config.Config, action func(*logging.LoggingIntegration, context.Context) error) error {
	logIntegration, err := logging.NewLoggingIntegration(cfg)
	if err != nil {
		return fmt.Errorf("failed to create logging integration: %w", err)
	}
	ctx := context.Background()
	if err := logIntegration.Start(ctx); err != nil {
		return fmt.Errorf("failed to start logging service: %w", err)
	}
	defer func() {
		if err := logIntegration.Stop(); err != nil {
			fmt.Printf("Warning: failed to stop logging service: %v\n", err)
		}
	}()
	return action(logIntegration, ctx)
}

func withLoggingIntegration(action func(*logging.LoggingIntegration, context.Context) error) {
	cfg, err := loadDefaultConfig()
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		osExit(1)
		return
	}
	release, err := acquireAgentLock()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		osExit(1)
		return
	}
	defer release()
	if err := withLoggingIntegrationForConfig(cfg, action); err != nil {
		fmt.Printf("Error: %v\n", err)
		osExit(1)
	}
}

func HandleCollectLogs() {
	fmt.Println("Collecting logs...")
	withLoggingIntegration(func(li *logging.LoggingIntegration, ctx context.Context) error {
		if err := li.CollectLogsNow(ctx); err != nil {
			return fmt.Errorf("failed to collect logs: %w", err)
		}
		fmt.Println("Log collection completed successfully")
		return nil
	})
}

func HandleUploadLogs() {
	fmt.Println("Uploading pending logs...")
	withLoggingIntegration(func(li *logging.LoggingIntegration, ctx context.Context) error {
		if err := li.ForceUpload(ctx); err != nil {
			fmt.Printf("Upload failed: %v (expected if Supabase URL is not configured)\n", err)
		}
		return nil
	})
}

func HandleLoggingStats() {
	withLoggingIntegration(func(li *logging.LoggingIntegration, ctx context.Context) error {
		stats := li.GetStatistics()
		fmt.Printf("Logging Statistics\n")
		fmt.Printf("Logs Collected: %d\n", stats.LogsCollected)
		fmt.Printf("Logs Stored: %d\n", stats.LogsStored)
		fmt.Printf("Logs Uploaded: %d\n", stats.LogsUploaded)
		fmt.Printf("Upload Errors: %d\n", stats.UploadErrors)
		fmt.Printf("Dropped (outside retention window): %d\n", stats.DroppedOutOfWindow)
		return nil
	})
}

// HandleEnableAutoUpdate sets auto_update=true in the config and saves it.
func HandleEnableAutoUpdate(cfgPath string) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		logFatalf("Failed to load config: %v", err)
		return
	}

	cfg.AutoUpdate = true
	if err := cfg.Save(); err != nil {
		logFatalf("Failed to save config: %v", err)
		return
	}
	fmt.Println("Auto-update enabled in config")
}

// HandleAgentInfoUpdate pushes current system info to the backend using the
// stored session.
//
// The CLI never refreshes tokens: Supabase rotates the refresh token on every
// refresh, so a refresh from this process would revoke the token family the
// running service depends on. If there is no stored access token, or it is
// rejected, the CLI does an agent-login in memory only (nothing is written to
// disk) and tries once more.
func HandleAgentInfoUpdate(cfg *config.Config) {
	fmt.Println("Updating agent information...")

	if cfg.GetAccessToken() == "" && (cfg.AgentID == "" || cfg.AgentSecret == "") {
		fmt.Println("No tokens or agent credentials in config – please register the agent first")
		return
	}

	// Collect first: it can take a while, and must not eat the network budget.
	sysInfo := collectOSInfo()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// A payload the server rejects is dropped by the enqueue retry policy;
	// have it reported so the operator is not told the update succeeded (#120).
	ctx = rpcutil.ReportDroppedPayloads(ctx)

	authSvc := authsvc.NewService(cfg.SupabaseURL, cfg.SupabaseKey)
	agentSvc := agentsvc.NewAgentService()
	update := func() error { return agentSvc.UpdateAgentInfo(ctx, cfg, sysInfo) }

	needLogin := cfg.GetAccessToken() == ""
	var err error
	if !needLogin {
		err = update()
		needLogin = authsvc.IsUnauthorized(err)
	}
	if needLogin {
		fmt.Println("Logging in for this command only (tokens are not saved)...")
		if lerr := authSvc.LoginInMemory(ctx, cfg); lerr != nil {
			fmt.Printf("Agent login failed: %v\n", sanitize.ForLog(lerr.Error()))
			return
		}
		err = update()
	}
	if err != nil {
		fmt.Printf("Agent info update failed: %v\n", err)
		return
	}

	fmt.Printf("Agent information updated successfully\n")
}
