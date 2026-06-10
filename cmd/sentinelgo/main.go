package main

import (
	"fmt"
	"log"

	"sentinelgo/cmd/sentinelgo/cli"
	svcsub "sentinelgo/cmd/sentinelgo/service"
	"sentinelgo/internal/config"
)

func main() {
	f := parseFlags()

	// CLI subcommands that don't require a loaded config.
	switch {
	case *f.collectLogs:
		cli.HandleCollectLogs()
		return
	case *f.uploadLogs:
		cli.HandleUploadLogs()
		return
	case *f.loggingStats:
		cli.HandleLoggingStats()
		return
	case *f.version:
		printVersion()
		return
	case *f.enableAutoUpdate:
		cli.HandleEnableAutoUpdate(*f.cfgPath)
		return
	}

	// Everything below needs a loaded config.
	cfg, err := config.Load(*f.cfgPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// CLI subcommands that operate on the config and then exit.
	if *f.agentTaskPolling {
		cli.HandleAgentTaskPolling(cfg)
		return
	}
	if *f.agentTaskExecution {
		cli.HandleAgentTaskExecution(cfg)
		return
	}
	if *f.agentTaskManager {
		cli.HandleAgentTaskManager(cfg)
		return
	}
	if *f.softwareSync {
		cli.HandleSoftwareSync(cfg)
		return
	}
	if *f.agentInfoUpdate {
		cli.HandleAgentInfoUpdate(cfg)
		return
	}
	if *f.runAuditLogs {
		cli.HandleAuditLogsStandalone(cfg)
		return
	}
	if *f.auditLogsStatus {
		cli.HandleAuditLogsStatus(cfg)
		return
	}
	if *f.softwareList || *f.softwareListJSON || *f.softwareListCount {
		cli.HandleSoftwareListCommand(*f.cfgPath, *f.softwareListJSON, *f.softwareListCount)
		return
	}
	if *f.stop {
		cli.HandleStop()
		return
	}

	if *f.run || (!*f.install && !*f.uninstall) {
		fmt.Println("Consider running './sentinelgo -stop' to stop old versions first")
		if !*f.run {
			fmt.Println("Or use './sentinelgo -run' to run in foreground mode")
		}
	}

	if *f.statusFlag {
		cli.HandleStatus()
		return
	}

	// Service lifecycle (install / uninstall / foreground run / run-as-service).
	prg := svcsub.NewProgram(cfg)

	svcCfg := svcsub.ServiceConfig{
		Name:        "SentinelGo",
		DisplayName: "SentinelGo Agent",
		Description: "Cross-platform agent to collect OS info and report heartbeat to Supabase",
		Arguments:   []string{"-config", cfg.Path},
	}

	svc, lgr, err := svcsub.NewAgentService(prg, svcCfg)
	if err != nil {
		log.Fatalf("Failed to create service: %v", err)
	}
	svcsub.SetLogger(lgr)
	svcsub.SetVersion(GetVersion())

	if *f.install {
		svcsub.HandleInstall(svc)
		return
	}
	if *f.uninstall {
		svcsub.HandleUninstall(svc)
		return
	}
	if *f.run {
		svcsub.RunForeground(cfg)
		return
	}

	svcsub.RunAsService(svc)
}
