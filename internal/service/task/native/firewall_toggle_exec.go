package native

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"

	"sentinelgo/internal/binpath"
)

// triggerFirewallDisable and triggerFirewallEnable actually toggle the host
// firewall. These are not, and should not be, unit-tested directly: doing so
// would disable/enable the firewall on whatever machine runs the test suite
// (developer laptop or CI runner). firewall_disable.go/firewall_enable.go's
// handler-level logic (permission checks, error wrapping, PostRun) is tested
// via the disableFirewallFn/enableFirewallFn injection seams instead; this
// file is excluded from the coverage gate in sonar-project.properties for the
// same reason.

func triggerFirewallDisable(ctx context.Context) error {
	return setFirewallState(ctx, false)
}

func triggerFirewallEnable(ctx context.Context) error {
	return setFirewallState(ctx, true)
}

func setFirewallState(ctx context.Context, enable bool) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		state := "disable"
		if enable {
			state = "enable"
		}
		// #nosec G204 -- binpath.Resolve returns one of a fixed set of
		// os.Stat-verified absolute paths (or the literal name unchanged);
		// it never forwards attacker-controlled input.
		cmd = exec.CommandContext(ctx, binpath.Resolve("ufw"), state)
	case "darwin":
		state := "off"
		if enable {
			state = "on"
		}
		cmd = exec.CommandContext(ctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", state)
	case "windows":
		state := "off"
		if enable {
			state = "on"
		}
		// #nosec G204 -- binpath.Resolve returns one of a fixed set of
		// os.Stat-verified absolute paths (or the literal name unchanged);
		// it never forwards attacker-controlled input.
		cmd = exec.CommandContext(ctx, binpath.Resolve("netsh"), "advfirewall", "set", "allprofiles", "state", state)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}
