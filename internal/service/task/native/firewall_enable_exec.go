package native

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"

	"sentinelgo/internal/binpath"
)

// triggerFirewallEnable actually enables the host firewall. This is not,
// and should not be, unit-tested directly: doing so would enable the
// firewall on whatever machine runs the test suite (developer laptop or CI
// runner), potentially breaking its own network access. firewall_enable.go's
// handler-level logic (permission checks, error wrapping, PostRun) is
// tested via the enableFirewallFn injection seam instead; this file is
// excluded from the coverage gate in sonar-project.properties for the same
// reason.
func triggerFirewallEnable(ctx context.Context) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.CommandContext(ctx, binpath.Resolve("ufw"), "enable")
	case "darwin":
		cmd = exec.CommandContext(ctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on")
	case "windows":
		cmd = exec.CommandContext(ctx, binpath.Resolve("netsh"), "advfirewall", "set", "allprofiles", "state", "on")
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}
