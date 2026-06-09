package agent

import (
	"os/exec"
	"strings"
)

// getHardwareModel retrieves hardware model on macOS via system_profiler.
func getHardwareModel() string {
	// #nosec G204 - fixed command with no user input
	cmd := exec.Command("system_profiler", "SPHardwareDataType")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	model := strings.TrimSpace(string(output))
	model = strings.ReplaceAll(model, "\n", "")
	model = strings.ReplaceAll(model, "\r", "")
	return model
}
