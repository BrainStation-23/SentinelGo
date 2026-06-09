package agent

import (
	"encoding/json"
	"os/exec"
)

// getHardwareModel retrieves hardware model on macOS via system_profiler.
func getHardwareModel() string {
	// #nosec G204 - fixed command with no user input
	cmd := exec.Command("system_profiler", "SPHardwareDataType", "-json")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	// Parse JSON to extract only the model name
	var result map[string]any
	if err := json.Unmarshal(output, &result); err != nil {
		return ""
	}

	if hardwareRaw, ok := result["SPHardwareDataType"]; ok {
		if hardwareArr, ok := hardwareRaw.([]any); ok && len(hardwareArr) > 0 {
			if hardware, ok := hardwareArr[0].(map[string]any); ok {
				if modelName, ok := hardware["machine_name"].(string); ok && modelName != "" {
					return modelName
				}
			}
		}
	}

	return ""
}
