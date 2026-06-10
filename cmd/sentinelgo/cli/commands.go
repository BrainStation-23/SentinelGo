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
	auditlogsvc "sentinelgo/internal/service/auditlog"
	authsvc "sentinelgo/internal/service/auth"
)

func HandleAuditLogsStandalone(cfg *config.Config) {
	fmt.Println("Starting audit logs service in standalone mode...")

	auditService := auditlogsvc.NewAuditLogService(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				appCfg := &auditlogsvc.AppConfig{
					ConfigPath:    cfg.Path,
					EventType:     "system_check",
					OSType:        runtime.GOOS,
					UptimeSeconds: 0,
				}

				batchData := auditService.CreateBatchData(appCfg)
				if err := auditService.SendBatchLogsWithContext(ctx, batchData); err != nil {
					log.Printf("Failed to send audit logs: %v", err)
				} else {
					log.Println("Audit logs sent successfully")
				}
			}
		}
	}()

	fmt.Println("Audit logs service is running. Press Ctrl+C to stop.")
	<-sigChan
	fmt.Println("\nAudit logs service stopped")
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

func withLoggingIntegration(action func(*logging.LoggingIntegration, context.Context) error) {
	cfg, err := config.Load("")
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		os.Exit(1)
	}

	logIntegration, err := logging.NewLoggingIntegration(cfg)
	if err != nil {
		fmt.Printf("Failed to create logging integration: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	if err := logIntegration.Start(ctx); err != nil {
		fmt.Printf("Failed to start logging service: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := logIntegration.Stop(); err != nil {
			fmt.Printf("Warning: failed to stop logging service: %v\n", err)
		}
	}()

	if err := action(logIntegration, ctx); err != nil {
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

// HandleAgentInfoUpdate refreshes auth (if possible) and pushes current system
// info to the backend.
func HandleAgentInfoUpdate(cfg *config.Config) {
	fmt.Println("Updating agent information...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	authSvc := authsvc.NewService(cfg.SupabaseURL, cfg.AccessToken)
	agentSvc := agentsvc.NewAgentService()

	if cfg.RefreshToken != "" {
		fmt.Println("Refreshing authentication token...")
		if err := authSvc.RefreshToken(ctx, cfg); err != nil {
			fmt.Printf("Token refresh failed: %v\n", err)
			fmt.Println("Continuing with stored token – update may fail if it is expired")
		} else {
			fmt.Println("Authentication token refreshed successfully")
		}
	} else if cfg.AccessToken == "" {
		fmt.Println("No tokens in config – please register the agent first")
		return
	}

	sysInfo := osinfo.Collect()

	if err := agentSvc.UpdateAgentInfo(ctx, cfg, sysInfo); err != nil {
		fmt.Printf("Agent info update failed: %v\n", err)
		return
	}

	fmt.Printf("Agent information updated successfully\n")
}
