package services

import (
	"context"
	"encoding/json"
	"log"
	"os/exec"
	"strings"
	"time"

	"sentinelgo/internal/models"
)

// platformServices collects Windows Services via CIM/WMI.
func (s *ServicesService) platformServices() []models.ServiceInfo {
	if items, ok := s.getWindowsServices(); ok {
		return items
	}
	return nil
}

// getWindowsServices queries Win32_Service via PowerShell CIM.
func (s *ServicesService) getWindowsServices() ([]models.ServiceInfo, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), collectCmdTimeout)
	defer cancel()

	query := `Get-CimInstance -ClassName Win32_Service | ` +
		`Select-Object Name,DisplayName,State,StartMode,Description,ProcessId,StartName | ` +
		`ConvertTo-Json -Compress`
	cmd := exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", query)
	output, err := cmd.Output()
	if err != nil {
		log.Printf("services: Win32_Service query failed: %v", err)
		return nil, false
	}

	svcs := parseWindowsServiceOutput(output)
	return svcs, true
}

// windowsServiceRecord mirrors the JSON fields returned by ConvertTo-Json for Win32_Service.
type windowsServiceRecord struct {
	Name        string  `json:"Name"`
	DisplayName string  `json:"DisplayName"`
	State       string  `json:"State"`
	StartMode   string  `json:"StartMode"`
	Description string  `json:"Description"`
	ProcessId   float64 `json:"ProcessId"` // JSON numbers decode as float64
	StartName   string  `json:"StartName"`
}

func parseWindowsServiceOutput(output []byte) []models.ServiceInfo {
	// PowerShell outputs either a JSON array or a single object when there is only one result.
	var records []windowsServiceRecord
	if err := json.Unmarshal(output, &records); err != nil {
		var single windowsServiceRecord
		if err2 := json.Unmarshal(output, &single); err2 != nil {
			log.Printf("services: failed to parse Win32_Service JSON: %v", err2)
			return nil
		}
		records = []windowsServiceRecord{single}
	}

	now := time.Now().UTC().Format(time.RFC3339)
	svcs := make([]models.ServiceInfo, 0, len(records))
	for _, r := range records {
		if r.Name == "" {
			continue
		}
		svcs = append(svcs, models.ServiceInfo{
			Name:        r.Name,
			DisplayName: r.DisplayName,
			Status:      normalizeWindowsState(r.State),
			StartType:   normalizeWindowsStartMode(r.StartMode),
			Description: r.Description,
			Source:      "windows_services",
			PID:         int(r.ProcessId),
			RunAs:       r.StartName,
			FirstSeenAt: now,
			UpdatedAt:   now,
		})
	}
	return svcs
}

// normalizeWindowsState maps Win32_Service State values to canonical lowercase strings.
func normalizeWindowsState(state string) string {
	switch strings.TrimSpace(state) {
	case "Running":
		return "running"
	case "Stopped":
		return "stopped"
	case "Paused":
		return "paused"
	case "Start Pending":
		return "starting"
	case "Stop Pending":
		return "stopping"
	case "Continue Pending", "Pause Pending":
		return "pending"
	default:
		if state == "" {
			return "unknown"
		}
		return strings.ToLower(state)
	}
}

// normalizeWindowsStartMode maps Win32_Service StartMode values to canonical strings.
func normalizeWindowsStartMode(mode string) string {
	switch strings.TrimSpace(mode) {
	case "Auto":
		return "automatic"
	case "Manual":
		return "manual"
	case "Disabled":
		return "disabled"
	case "Boot":
		return "boot"
	case "System":
		return "system"
	default:
		if mode == "" {
			return "unknown"
		}
		return strings.ToLower(mode)
	}
}
