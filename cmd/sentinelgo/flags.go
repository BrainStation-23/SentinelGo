package main

import "flag"

// cliFlags holds all parsed command-line flags.
type cliFlags struct {
	cfgPath            *string
	install            *bool
	uninstall          *bool
	run                *bool
	statusFlag         *bool
	stop               *bool
	enableAutoUpdate   *bool
	softwareSync       *bool
	agentInfoUpdate    *bool
	softwareList       *bool
	softwareListJSON   *bool
	softwareListCount  *bool
	servicesList       *bool
	servicesListJSON   *bool
	servicesListCount  *bool
	collectLogs        *bool
	uploadLogs         *bool
	loggingStats       *bool
	version            *bool
	runAuditLogs       *bool
	auditLogsStatus    *bool
	agentTaskPolling   *bool
	agentTaskExecution *bool
	agentTaskManager   *bool
}

func parseFlags() *cliFlags {
	f := &cliFlags{
		cfgPath:            flag.String("config", "", "Path to config file (optional)"),
		install:            flag.Bool("install", false, "Install service"),
		uninstall:          flag.Bool("uninstall", false, "Uninstall service"),
		run:                flag.Bool("run", false, "Run in foreground (console mode)"),
		statusFlag:         flag.Bool("status", false, "Show running SentinelGo processes and versions"),
		stop:               flag.Bool("stop", false, "Stop all running SentinelGo processes"),
		enableAutoUpdate:   flag.Bool("enable-auto-update", false, "Enable automatic updates"),
		softwareSync:       flag.Bool("software-sync", false, "Run software sync service"),
		agentInfoUpdate:    flag.Bool("agent-info-update", false, "Update agent information"),
		softwareList:       flag.Bool("software-list", false, "Show installed software list"),
		softwareListJSON:   flag.Bool("software-list-json", false, "Show software list as JSON"),
		softwareListCount:  flag.Bool("software-list-count", false, "Show total software count only"),
		servicesList:       flag.Bool("services-list", false, "Show running OS services list"),
		servicesListJSON:   flag.Bool("services-list-json", false, "Show OS services list as JSON"),
		servicesListCount:  flag.Bool("services-list-count", false, "Show total services count only"),
		collectLogs:        flag.Bool("collect-logs", false, "Force immediate log collection"),
		uploadLogs:         flag.Bool("upload-logs", false, "Force upload of pending logs"),
		loggingStats:       flag.Bool("logging-stats", false, "Show logging statistics"),
		version:            flag.Bool("version", false, "Show version information"),
		runAuditLogs:       flag.Bool("audit-logs", false, "Run audit logs service (standalone mode)"),
		auditLogsStatus:    flag.Bool("audit-logs-status", false, "Show audit logs service status"),
		agentTaskPolling:   flag.Bool("agent-task-polling", false, "Show agent task polling status"),
		agentTaskExecution: flag.Bool("agent-task-execution", false, "Show agent task execution status"),
		agentTaskManager:   flag.Bool("agent-task-manager", false, "Run integrated task polling and execution service"),
	}
	flag.Parse()
	return f
}
