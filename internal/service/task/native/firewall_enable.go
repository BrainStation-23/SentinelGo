package native

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"sentinelgo/internal/config"
	"sentinelgo/internal/taskstore"
)

// enableFirewallFn is the OS firewall-enable entry point. Replaced in tests.
var enableFirewallFn = triggerFirewallEnable

type firewallEnableHandler struct{}

func init() { Register(&firewallEnableHandler{}) }

func (h *firewallEnableHandler) Slugs() []string {
	return []string{"firewall-enable"}
}

// Enable the host firewall (e.g. ufw/iptables on Linux, Windows Firewall, pf on macOS)
func (h *firewallEnableHandler) Run(ctx context.Context, _ *config.Config, _ taskstore.Task) (string, error) {
	switch runtime.GOOS {
	case "linux", "darwin":
		if os.Getuid() != 0 {
			return "", fmt.Errorf("firewall-enable requires root privileges on %s", runtime.GOOS)
		}
	}
	if err := enableFirewallFn(ctx); err != nil {
		return "", fmt.Errorf("firewall-enable: %w", err)
	}
	return "firewall enabled successfully", nil
}

func (h *firewallEnableHandler) PostRun() []string {
	return []string{"sync-inventory"}
}
