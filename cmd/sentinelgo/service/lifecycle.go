package service

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"sentinelgo/internal"
	"sentinelgo/internal/config"
	"sentinelgo/internal/lockfile"
	"sentinelgo/internal/sanitize"
)

// HandleInstall installs SentinelGo as a system service (launchd on macOS,
// platform-native elsewhere) and starts it.
func HandleInstall(svc AgentService) {
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

// HandleUninstall removes the SentinelGo system service.
func HandleUninstall(svc AgentService) {
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

// RunForeground runs the agent in console/foreground mode, guarded by a process
// lock, until an interrupt signal is received.
func RunForeground(cfg *config.Config) {
	version := config.Version
	lf := lockfile.NewLockFile(fmt.Sprintf("sentinelgo-%s", version))

	locked, err := lf.CheckExistingLock()
	if err != nil {
		log.Printf("Warning: Failed to check existing lock: %v", err)
	} else if locked {
		sanitizedVersion := sanitize.ForLog(version)
		log.Printf("Another instance of SentinelGo v%s is already running", sanitizedVersion)
		fmt.Printf("Error: Another instance of SentinelGo v%s is already running\n", sanitizedVersion)
		fmt.Println("Use './sentinelgo -stop' to stop the running instance first")
		return
	}

	if err := lf.TryAcquire(); err != nil {
		log.Printf("Failed to acquire process lock: %v", err)
		fmt.Printf("Error: Failed to acquire process lock: %v\n", err)
		return
	}
	defer func() {
		if err := lf.Release(); err != nil {
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

// RunAsService hands control to the platform service manager.
func RunAsService(svc AgentService) {
	if err := svc.Run(); err != nil {
		if err := logger.Errorf("Service failed: %v", err); err != nil {
			log.Printf("Warning: failed to log service error: %v", err)
		}
	}
}
