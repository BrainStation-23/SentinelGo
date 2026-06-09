package shared

import (
	"context"
	"os"
	"os/exec"
	"time"
)

func ReadFileContent(path string) (string, error) {
	// #nosec G304 - path is a controlled internal parameter
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func ReadFileBytes(path string) ([]byte, error) {
	// #nosec G304 - path is a controlled internal parameter
	return os.ReadFile(path)
}

func RunCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// #nosec G204 - name and args are controlled internal parameters
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}
