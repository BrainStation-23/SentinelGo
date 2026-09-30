package native

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"

	"sentinelgo/internal/binpath"
)

// triggerFirewallDisable actually disables the host firewall. This is not,
// and should not be, unit-tested directly: doing so would disable the
// firewall on whatever machine runs the test suite (developer laptop or CI
// runner). firewall_disable.go's handler-level logic (permission checks,
// error wrapping, PostRun) is tested via the disableFirewallFn injection
// seam instead; this file is excluded from the coverage gate in
// sonar-project.properties for the same reason.
func triggerFirewallDisable(ctx context.Context) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.CommandContext(ctx, binpath.Resolve("ufw"), "disable")
	case "darwin":
		cmd = exec.CommandContext(ctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "off")
	case "windows":
		cmd = exec.CommandContext(ctx, binpath.Resolve("netsh"), "advfirewall", "set", "allprofiles", "state", "off")
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}
