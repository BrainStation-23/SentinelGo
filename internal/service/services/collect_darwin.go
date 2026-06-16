package services

import (
	"context"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"sentinelgo/internal/models"
)

// platformServices collects launchd services on macOS via launchctl list.
func (s *ServicesService) platformServices() []models.ServiceInfo {
	if items, ok := s.getLaunchdServices(); ok {
		return items
	}
	return nil
}

// getLaunchdServices runs `launchctl list` and parses the output.
func (s *ServicesService) getLaunchdServices() ([]models.ServiceInfo, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), collectCmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "launchctl", "list")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("services: launchctl list failed: %v", err)
		return nil, false
	}
	return parseLaunchctlList(output), true
}

// parseLaunchctlList parses `launchctl list` output.
// Format: PID\tStatus\tLabel (tab-separated, first line is header).
//
// PID is "-" when the job is not running; Status is the last exit code ("-" when
// running). A PID that is not "-" means the service is currently running.
func parseLaunchctlList(output []byte) []models.ServiceInfo {
	now := time.Now().UTC().Format(time.RFC3339)
	var svcs []models.ServiceInfo

	for i, line := range strings.Split(string(output), "\n") {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // skip header and blank lines
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) != 3 {
			continue
		}
		pidStr := strings.TrimSpace(parts[0])
		statusStr := strings.TrimSpace(parts[1])
		label := strings.TrimSpace(parts[2])
		if label == "" {
			continue
		}

		pid := 0
		if pidStr != "-" {
			if v, err := strconv.Atoi(pidStr); err == nil {
				pid = v
			}
		}

		status := darwinStatus(pidStr, statusStr)
		startType := inferDarwinStartType(label)

		svcs = append(svcs, models.ServiceInfo{
			Name:        label,
			DisplayName: label,
			Status:      status,
			StartType:   startType,
			Source:      "launchd",
			PID:         pid,
			FirstSeenAt: now,
			UpdatedAt:   now,
		})
	}
	return svcs
}

// darwinStatus maps launchctl PID/Status columns to a canonical status string.
func darwinStatus(pidStr, statusStr string) string {
	if pidStr != "-" {
		return "running"
	}
	// Service is not running. A non-zero, non-"-" status code means it failed.
	if statusStr != "0" && statusStr != "-" {
		return "failed"
	}
	return "stopped"
}

// inferDarwinStartType infers a start type from the launchd label convention.
// Apple system labels follow the com.apple.* namespace; third-party labels are
// treated as on-demand. This is a best-effort heuristic for the first iteration.
func inferDarwinStartType(label string) string {
	switch {
	case strings.HasPrefix(label, "com.apple.") || strings.HasPrefix(label, "com.Apple."):
		return "system"
	default:
		return "unknown"
	}
}
