package main

import (
	"fmt"
	"log"

	"sentinelgo/internal/config"

	svcc "github.com/kardianos/service"
)

func main() {
	f := parseFlags()

	// CLI subcommands that don't require a loaded config.
	switch {
	case *f.collectLogs:
		handleCollectLogs()
		return
	case *f.uploadLogs:
		handleUploadLogs()
		return
	case *f.loggingStats:
		handleLoggingStats()
		return
	case *f.version:
		printVersion()
		return
	case *f.enableAutoUpdate:
		handleEnableAutoUpdate(*f.cfgPath)
		return
	}

	// Everything below needs a loaded config.
	cfg, err := config.Load(*f.cfgPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// CLI subcommands that operate on the config and then exit.
	if *f.agentTaskPolling {
		handleAgentTaskPolling(cfg)
		return
	}
	if *f.agentTaskExecution {
		handleAgentTaskExecution(cfg)
		return
	}
	if *f.agentTaskManager {
		handleAgentTaskManager(cfg)
		return
	}
	if *f.softwareSync {
		handleSoftwareSync(cfg)
		return
	}
	if *f.agentInfoUpdate {
		handleAgentInfoUpdate(cfg)
		return
	}
	if *f.runAuditLogs {
		handleAuditLogsStandalone(cfg)
		return
	}
	if *f.auditLogsStatus {
		handleAuditLogsStatus(cfg)
		return
	}
	if *f.softwareList || *f.softwareListJSON || *f.softwareListCount {
		handleSoftwareListCommand(*f.cfgPath, *f.softwareListJSON, *f.softwareListCount)
		return
	}
	if *f.stop {
		handleStop()
		return
	}

	if *f.run || (!*f.install && !*f.uninstall) {
		fmt.Println("Consider running './sentinelgo -stop' to stop old versions first")
		if !*f.run {
			fmt.Println("Or use './sentinelgo -run' to run in foreground mode")
		}
	}

	if *f.statusFlag {
		handleStatus()
		return
	}

	// Service lifecycle (install / uninstall / foreground run / run-as-service).
	prg := &program{cfg: cfg}

	svcCfg := &svcc.Config{
		Name:        "SentinelGo",
		DisplayName: "SentinelGo Agent",
		Description: "Cross-platform agent to collect OS info and report heartbeat to Supabase",
		Arguments:   []string{"-config", cfg.Path},
		Option:      svcc.KeyValue{"StartType": "automatic"},
	}

	svc, err := svcc.New(prg, svcCfg)
	if err != nil {
		log.Fatalf("Failed to create service: %v", err)
	}

	logger, err = svc.Logger(nil)
	if err != nil {
		log.Fatalf("Failed to get service logger: %v", err)
	}

	if *f.install {
		handleInstall(svc)
		return
	}
	if *f.uninstall {
		handleUninstall(svc)
		return
	}
	if *f.run {
		runForeground(cfg)
		return
	}

	runAsService(svc)
}
