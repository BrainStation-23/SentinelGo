package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"sentinelgo/internal"
	"sentinelgo/internal/config"
	"sentinelgo/internal/lockfile"
	"sentinelgo/internal/sanitize"
	auditlogsvc "sentinelgo/internal/service/auditlog"

	svcc "github.com/kardianos/service"
)

type program struct {
	cfg             *config.Config
	lockFile        *lockfile.LockFile
	mainIntegration *internal.MainIntegration
	auditService    *auditlogsvc.AuditLogService
	ctx             context.Context
	cancel          context.CancelFunc
}

func (p *program) Start(s svcc.Service) error {
	if err := logger.Info("Starting SentinelGo service"); err != nil {
		fmt.Printf("Warning: failed to log start message: %v\n", err)
	}

	if p.cfg == nil {
		var err error
		p.cfg, err = config.Load("")
		if err != nil {
			log.Printf("FATAL: Failed to load config: %v", err)
			return fmt.Errorf("failed to load config: %w", err)
		}
	}

	version := GetVersion()
	if version == "" {
		version = "unknown"
	}
	sanitizedVersion := sanitize.ForLog(version)
	lockFile := lockfile.NewLockFile(fmt.Sprintf("sentinelgo-%s", sanitizedVersion))

	locked, err := lockFile.CheckExistingLock()
	if err != nil {
		log.Printf("Warning: Failed to check existing lock: %v", err)
	} else if locked {
		log.Printf("Another instance of SentinelGo v%s is already running", sanitizedVersion)
		return fmt.Errorf("another instance is already running")
	}

	if err := lockFile.TryAcquire(); err != nil {
		log.Printf("Failed to acquire process lock: %v", err)
		return fmt.Errorf("failed to acquire process lock: %v", err)
	}
	p.lockFile = lockFile

	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.mainIntegration = internal.NewMainIntegration(p.cfg)

	go func() {
		if err := p.mainIntegration.Start(p.ctx); err != nil {
			log.Printf("Main integration stopped with error: %v", err)
		}
	}()

	if p.cfg.AuditLogsEnabled {
		p.auditService = auditlogsvc.NewAuditLogService(p.cfg)
		go p.runAuditLogsService()
		log.Println("Audit logs service started")
	}

	return nil
}

func (p *program) runAuditLogsService() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			log.Println("Audit logs service stopped")
			return
		case <-ticker.C:
			appCfg := &auditlogsvc.AppConfig{
				ConfigPath:    p.cfg.Path,
				EventType:     "system_check",
				OSType:        runtime.GOOS,
				UptimeSeconds: 0,
			}

			batchData := p.auditService.CreateBatchData(appCfg)
			if err := p.auditService.SendBatchLogsWithContext(p.ctx, batchData); err != nil {
				log.Printf("Failed to send audit logs: %v", err)
			} else {
				log.Println("Audit logs sent successfully")
			}
		}
	}
}

func (p *program) Stop(s svcc.Service) error {
	if err := logger.Info("Stopping SentinelGo service"); err != nil {
		fmt.Printf("Warning: failed to log stop message: %v\n", err)
	}

	if p.cancel != nil {
		p.cancel()
	}

	if p.mainIntegration != nil {
		if err := p.mainIntegration.Stop(); err != nil {
			log.Printf("Warning: Failed to stop main integration: %v", err)
		}
	}

	if p.lockFile != nil {
		if err := p.lockFile.Release(); err != nil {
			if err := logger.Errorf("Failed to release process lock: %v", err); err != nil {
				fmt.Printf("Warning: failed to log error: %v\n", err)
			}
		} else {
			if err := logger.Info("Released process lock"); err != nil {
				fmt.Printf("Warning: failed to log info: %v\n", err)
			}
		}
	}

	return nil
}

// handleInstall installs SentinelGo as a system service (launchd on macOS,
// kardianos/service elsewhere) and starts it.
func handleInstall(svc svcc.Service) {
	if runtime.GOOS == "darwin" {
		fmt.Println("Installing SentinelGo as launchd service...")

		if err := createLaunchdPlist(); err != nil {
			log.Fatalf("Failed to create launchd plist: %v", err)
		}

		if err := loadLaunchdService(); err != nil {
			log.Fatalf("Failed to load launchd service: %v", err)
		}

		startCmd := exec.Command("launchctl", "start", "com.sentinelgo.agent")
		if err := startCmd.Run(); err != nil {
			log.Printf("Warning: launchctl start failed (service may already be running): %v", err)
		}

		fmt.Println("SentinelGo service installed and started successfully!")
		fmt.Println("Service will start automatically on system boot.")
		fmt.Println("Logs: /var/log/sentinelgo.log and /var/log/sentinelgo.err")
		return
	}

	if err := svc.Install(); err != nil {
		log.Fatalf("Failed to install service: %v", err)
	}
	if err := logger.Info("Service installed"); err != nil {
		log.Printf("Warning: failed to log service installation: %v", err)
	}

	if err := svc.Start(); err != nil {
		log.Printf("Warning: failed to start service: %v", err)
		return
	}
	if err := logger.Info("Service started"); err != nil {
		log.Printf("Warning: failed to log service start: %v", err)
	}
	fmt.Println("SentinelGo service installed and started successfully!")
	if runtime.GOOS == "windows" {
		fmt.Println("Service will start automatically on system boot.")
	}
}

// handleUninstall removes the SentinelGo system service.
func handleUninstall(svc svcc.Service) {
	if runtime.GOOS == "darwin" {
		fmt.Println("Uninstalling SentinelGo launchd service...")

		if err := unloadLaunchdService(); err != nil {
			log.Printf("Warning: Failed to unload launchd service: %v", err)
		}

		if err := removeLaunchdPlist(); err != nil {
			log.Fatalf("Failed to remove launchd plist: %v", err)
		}

		fmt.Println("SentinelGo service uninstalled successfully!")
		return
	}

	if err := svc.Uninstall(); err != nil {
		log.Fatalf("Failed to uninstall service: %v", err)
	}
	if err := logger.Info("Service uninstalled"); err != nil {
		log.Fatalf("Failed to log service uninstallation: %v", err)
	}
}

// runForeground runs the agent in console/foreground mode, guarded by a process
// lock, until an interrupt signal is received.
func runForeground(cfg *config.Config) {
	version := config.Version
	lockFile := lockfile.NewLockFile(fmt.Sprintf("sentinelgo-%s", version))

	locked, err := lockFile.CheckExistingLock()
	if err != nil {
		log.Printf("Warning: Failed to check existing lock: %v", err)
	} else if locked {
		sanitizedVersion := sanitize.ForLog(version)
		log.Printf("Another instance of SentinelGo v%s is already running", sanitizedVersion)
		fmt.Printf("Error: Another instance of SentinelGo v%s is already running\n", sanitizedVersion)
		fmt.Println("Use './sentinelgo -stop' to stop the running instance first")
		return
	}

	if err := lockFile.TryAcquire(); err != nil {
		log.Printf("Failed to acquire process lock: %v", err)
		fmt.Printf("Error: Failed to acquire process lock: %v\n", err)
		return
	}
	defer func() {
		if err := lockFile.Release(); err != nil {
			log.Printf("Warning: Failed to release lock: %v", err)
		}
	}()

	fmt.Printf("Started SentinelGo v%s in foreground mode\n", version)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	mainIntegration := internal.NewMainIntegration(cfg)

	go func() {
		if err := mainIntegration.Start(ctx); err != nil {
			log.Printf("Main integration stopped with error: %v", err)
		}
	}()

	<-sigChan
	fmt.Println("\nReceived shutdown signal, stopping...")
	cancel()
	if err := mainIntegration.Stop(); err != nil {
		log.Printf("Warning: Failed to stop main integration: %v", err)
	}
	fmt.Println("SentinelGo stopped")
}

// runAsService runs the agent under the platform service manager.
func runAsService(svc svcc.Service) {
	if err := svc.Run(); err != nil {
		if err := logger.Errorf("Service failed: %v", err); err != nil {
			log.Printf("Warning: failed to log service error: %v", err)
		}
	}
}
