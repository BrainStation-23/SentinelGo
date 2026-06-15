package native

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"sentinelgo/internal/config"
	"sentinelgo/internal/taskstore"
)

// disableFirewallFn is the OS firewall-disable entry point. Replaced in tests.
var disableFirewallFn = triggerFirewallDisable

type firewallDisableHandler struct{}

func init() { Register(&firewallDisableHandler{}) }

func (h *firewallDisableHandler) Slugs() []string {
	return []string{"firewall-disable"}
}

// Disable the host firewall (e.g. ufw/iptables on Linux, Windows Firewall, pf on macOS)
func (h *firewallDisableHandler) Run(ctx context.Context, _ *config.Config, _ taskstore.Task) (string, error) {
	switch runtime.GOOS {
	case "linux", "darwin":
		if os.Getuid() != 0 {
			return "", fmt.Errorf("firewall-disable requires root privileges on %s", runtime.GOOS)
		}
	}
	if err := disableFirewallFn(ctx); err != nil {
		return "", fmt.Errorf("firewall-disable: %w", err)
	}
	return "firewall disabled successfully", nil
}

func (h *firewallDisableHandler) PostRun() []string {
	return []string{"sync-inventory"}
}

func triggerFirewallDisable(ctx context.Context) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.CommandContext(ctx, "ufw", "disable")
	case "darwin":
		cmd = exec.CommandContext(ctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "off")
	case "windows":
		cmd = exec.CommandContext(ctx, "netsh", "advfirewall", "set", "allprofiles", "state", "off")
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}
