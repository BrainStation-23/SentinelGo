package service

// AgentService abstracts platform-specific service lifecycle operations.
// Implementations live in svc_windows.go, svc_linux.go, and svc_darwin.go.
type AgentService interface {
	Install() error
	Start() error
	Uninstall() error
	Run() error
}

// AgentLogger abstracts platform-specific service event logging.
type AgentLogger interface {
	Info(a ...interface{}) error
	Errorf(format string, a ...interface{}) error
}

// ServiceConfig holds the static metadata used to register the agent as a
// system service.
type ServiceConfig struct {
	Name        string
	DisplayName string
	Description string
	Arguments   []string
}

// logger is the package-level service logger, set by main after NewAgentService.
var logger AgentLogger

// SetLogger stores the AgentLogger produced by NewAgentService so that
// program lifecycle methods can use it without threading it through every call.
func SetLogger(l AgentLogger) { logger = l }

// agentVersion is the build-time version string, forwarded from main via SetVersion.
var agentVersion string

// SetVersion stores the injected version string so that service lifecycle
// code (launchd plist, lock-file names) can reference it without importing main.
func SetVersion(v string) { agentVersion = v }
