package main

import (
	"fmt"
	"log"
	"os"

	"sentinelgo/cmd/sentinelgo/cli"
	svcsub "sentinelgo/cmd/sentinelgo/service"
	"sentinelgo/internal/config"
)

func main() {
	// The DLP session helper runs before flag parsing, config loading and the
	// process lock: it is launched per user session and holds no credentials.
	// It is a positional subcommand so it stays out of -help.
	if len(os.Args) > 1 && os.Args[1] == cli.DLPSessionCommand {
		os.Exit(cli.RunDLPSession())
	}
	// A file DLP scan worker: started by the service, sandboxed, no config.
	if len(os.Args) > 1 && os.Args[1] == cli.DLPScanCommand {
		os.Exit(cli.RunDLPScan())
	}
	// `sentinelgo dlp status|test`: diagnostics from the cached policy.
	if len(os.Args) > 1 && os.Args[1] == cli.DLPCommand {
		os.Exit(cli.RunDLP(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	// `sentinelgo enroll`: save a first-boot enrollment token (installers).
	if len(os.Args) > 1 && os.Args[1] == cli.EnrollCommand {
		os.Exit(cli.RunEnroll(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	// `sentinelgo mdm status`: the device's MDM state, for support.
	if len(os.Args) > 1 && os.Args[1] == cli.MDMCommand {
		os.Exit(cli.RunMDM(os.Args[2:], os.Stdout, os.Stderr))
	}
	// `sentinelgo local-admin expire <grant_id>`: the backup OS task that
	// ends a time-limited admin grant if the service isn't running (#388).
	if len(os.Args) > 1 && os.Args[1] == cli.LocalAdminCommand {
		os.Exit(cli.RunLocalAdmin(os.Args[2:], os.Stdout, os.Stderr))
	}

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
	case *f.debugDump:
		cli.HandleDebugDump()
		return
	case *f.osInfoJSON:
		cli.HandleOSInfoDump()
		return
	case *f.auditLogsDump:
		cli.HandleAuditLogsDump()
		return
	}

	// Everything below needs a loaded config.
	cfg, err := config.Load(*f.cfgPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if dispatchConfigFlags(f, cfg) {
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

	runServiceLifecycle(f, cfg)
}

// dispatchConfigFlags handles CLI subcommands that need an already-loaded config.
// Returns true if a subcommand was dispatched (caller should return after).
func dispatchConfigFlags(f *cliFlags, cfg *config.Config) bool {
	switch {
	case *f.agentTaskPolling:
		cli.HandleAgentTaskPolling(cfg)
	case *f.agentTaskExecution:
		cli.HandleAgentTaskExecution(cfg)
	case *f.agentTaskManager:
		cli.HandleAgentTaskManager(cfg)
	case *f.softwareSync:
		cli.HandleSoftwareSync(cfg)
	case *f.agentInfoUpdate:
		cli.HandleAgentInfoUpdate(cfg)
	case *f.runAuditLogs:
		cli.HandleAuditLogsStandalone(cfg)
	case *f.auditLogsStatus:
		cli.HandleAuditLogsStatus(cfg)
	case *f.softwareList || *f.softwareListJSON || *f.softwareListCount:
		cli.HandleSoftwareListCommand(cfg.Path, *f.softwareListJSON, *f.softwareListCount)
	case *f.servicesList || *f.servicesListJSON || *f.servicesListCount:
		cli.HandleServicesListCommand(cfg.Path, *f.servicesListJSON, *f.servicesListCount)
	case *f.stop:
		cli.HandleStop()
	default:
		return false
	}
	return true
}

// runServiceLifecycle handles install / uninstall / foreground / service modes.
func runServiceLifecycle(f *cliFlags, cfg *config.Config) {
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

	switch {
	case *f.install:
		svcsub.HandleInstall(svc)
	case *f.uninstall:
		svcsub.HandleUninstall(svc)
	case *f.run:
		if err := svcsub.RunForeground(prg); err != nil {
			os.Exit(int(svcsub.StartExitCode(err)))
		}
	default:
		svcsub.RunAsService(svc)
	}
}
