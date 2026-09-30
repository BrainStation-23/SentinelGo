package native

import (
	"fmt"
	"os/exec"
	"runtime"

	"sentinelgo/internal/binpath"
)

// triggerReboot actually reboots the host. This is not, and should not be,
// unit-tested directly: doing so would reboot whatever machine runs the test
// suite (developer laptop or CI runner). reboot_device.go's handler-level
// logic (privilege checks, restart-context bookkeeping, error wrapping) is
// tested via the rebootFn injection seam instead; this file is excluded from
// the coverage gate in sonar-project.properties for the same reason.
func triggerReboot() error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux", "darwin":
		// #nosec G204 - binpath.Resolve returns a fixed, verified absolute path or the literal name; not attacker input
		cmd = exec.Command(binpath.Resolve("shutdown"), "-r", "now")
	case "windows":
		// #nosec G204 - binpath.Resolve returns a fixed, verified absolute path or the literal name; not attacker input
		cmd = exec.Command(binpath.Resolve("shutdown"), "/r", "/t", "0")
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
	return cmd.Run()
}
