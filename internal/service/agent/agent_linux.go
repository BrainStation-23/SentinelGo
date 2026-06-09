package agent

import (
	"os/exec"
	"strings"
)

// getHardwareModel retrieves hardware model on Linux by trying DMI sysfs
// entries and dmidecode in priority order.
func getHardwareModel() string {
	methods := [][]string{
		{"cat", "/sys/class/dmi/id/product_name"},
		{"cat", "/sys/class/dmi/id/product_version"},
		{"cat", "/sys/class/dmi/id/board_name"},
		{"dmidecode", "-s", "system-product-name"},
		{"cat", "/proc/cpuinfo"},
	}

	for _, method := range methods {
		var cmd *exec.Cmd
		switch len(method) {
		case 1:
			// #nosec G204 - method is a controlled internal parameter
			cmd = exec.Command(method[0])
		case 2:
			// #nosec G204 - method is a controlled internal parameter
			cmd = exec.Command(method[0], method[1])
		default:
			// #nosec G204 - method is a controlled internal parameter
			cmd = exec.Command(method[0], method[1:]...)
		}

		output, err := cmd.Output()
		if err != nil {
			continue
		}
		model := strings.TrimSpace(string(output))
		model = strings.ReplaceAll(model, "\n", "")
		model = strings.ReplaceAll(model, "\r", "")
		if model != "" && !strings.Contains(strings.ToLower(model), "unknown") && len(model) > 3 {
			return model
		}
	}

	return ""
}
