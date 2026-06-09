package agent

import (
	"os/exec"
	"strings"
)

// getHardwareModel retrieves hardware model on Windows using Get-CimInstance.
func getHardwareModel() string {
	// #nosec G204 - fixed command with no user input
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		"Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Model")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	model := strings.TrimSpace(string(output))
	model = strings.ReplaceAll(model, "\n", "")
	model = strings.ReplaceAll(model, "\r", "")
	return model
}
