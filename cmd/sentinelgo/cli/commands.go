package cli

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/logging"
	"sentinelgo/internal/osinfo"
	agentsvc "sentinelgo/internal/service/agent"
	authsvc "sentinelgo/internal/service/auth"
)

func HandleAuditLogsStandalone(cfg *config.Config) {
	fmt.Println("Starting audit logs service in standalone mode...")

	li, err := logging.NewLoggingIntegration(cfg)
	if err != nil {
		fmt.Printf("Failed to create logging integration: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := li.Start(ctx); err != nil {
		fmt.Printf("Failed to start logging service: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Audit logs service is running. Press Ctrl+C to stop.")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nStopping audit logs service...")
	if err := li.Stop(); err != nil {
		fmt.Printf("Warning: failed to stop logging service: %v\n", err)
	}
}

func HandleAuditLogsStatus(cfg *config.Config) {
	fmt.Println("Audit Logs Service Status")
	fmt.Println("=========================")
	fmt.Printf("Service Enabled: %v\n", cfg.AuditLogsEnabled)
	fmt.Printf("Device ID: %s\n", cfg.DeviceID)
	fmt.Printf("Agent Version: %s\n", cfg.CurrentVersion)
	fmt.Printf("OS Type: %s\n", runtime.GOOS)

	if cfg.AuditLogsEnabled {
		fmt.Println("\nStatus: Service is configured to run with the main agent")
	} else {
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
	cfg, err := config.Load("")
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		os.Exit(1)
	}
	if err := withLoggingIntegrationForConfig(cfg, action); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
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
		return nil
	})
}

// HandleEnableAutoUpdate sets auto_update=true in the config and saves it.
func HandleEnableAutoUpdate(cfgPath string) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	cfg.AutoUpdate = true
	if err := cfg.Save(); err != nil {
		log.Fatalf("Failed to save config: %v", err)
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
	sysInfo := osinfo.Collect()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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
			fmt.Printf("Agent login failed: %v\n", lerr)
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
