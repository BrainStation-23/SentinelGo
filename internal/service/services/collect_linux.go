package services

import (
	"context"
	"log"
	"os/exec"
	"strings"
	"time"

	"sentinelgo/internal/models"
)

// platformServices collects systemd service units on Linux.
func (s *ServicesService) platformServices() []models.ServiceInfo {
	units := make(map[string]models.ServiceInfo)

	if ok := s.collectSystemdUnits(units); !ok {
		log.Printf("services: systemctl list-units failed; service data may be incomplete")
	}
	s.mergeUnitFiles(units)

	now := time.Now().UTC().Format(time.RFC3339)
	svcs := make([]models.ServiceInfo, 0, len(units))
	for _, svc := range units {
		if svc.FirstSeenAt == "" {
			svc.FirstSeenAt = now
		}
		if svc.UpdatedAt == "" {
			svc.UpdatedAt = now
		}
		svcs = append(svcs, svc)
	}
	return svcs
}

// collectSystemdUnits populates units from `systemctl list-units --type=service --all`.
// Returns false if the command fails entirely.
func (s *ServicesService) collectSystemdUnits(units map[string]models.ServiceInfo) bool {
	ctx, cancel := context.WithTimeout(context.Background(), collectCmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("services: systemctl list-units failed: %v", err)
		return false
	}
	parseSystemdUnits(output, units)
	return true
}

// mergeUnitFiles enriches units with start_type from `systemctl list-unit-files`.
func (s *ServicesService) mergeUnitFiles(units map[string]models.ServiceInfo) {
	ctx, cancel := context.WithTimeout(context.Background(), collectCmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "systemctl", "list-unit-files", "--type=service", "--no-pager", "--no-legend")
	output, err := cmd.Output()
	if err != nil {
		log.Printf("services: systemctl list-unit-files failed: %v", err)
		return
	}
	startTypes := parseSystemdUnitFiles(output)

	// Add start_type to existing units and create entries for units not currently loaded.
	now := time.Now().UTC().Format(time.RFC3339)
	for name, startType := range startTypes {
		if svc, ok := units[name]; ok {
			svc.StartType = startType
			units[name] = svc
		} else {
			units[name] = models.ServiceInfo{
				Name:        name,
				DisplayName: name,
				Status:      "inactive",
				StartType:   startType,
				Source:      "systemd",
				FirstSeenAt: now,
				UpdatedAt:   now,
			}
		}
	}
}

// parseSystemdUnits parses the `--no-legend` output of systemctl list-units.
// Format per line (space-separated, variable columns):
//
//	[●|○|…] <unit>  <load>  <active>  <sub>  <description…>
//
// The leading status glyph is optional. Description runs to end of line.
func parseSystemdUnits(output []byte, units map[string]models.ServiceInfo) {
	now := time.Now().UTC().Format(time.RFC3339)
	for _, line := range strings.Split(string(output), "\n") {
		// Strip ANSI escape codes and leading/trailing space.
		line = strings.TrimSpace(stripANSI(line))
		if line == "" {
			break // blank line signals the end of the unit list
		}

		// Strip leading status glyph (●, ○, or similar Unicode).
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// The first field may be a non-ASCII bullet; if so, discard it.
		idx := 0
		if !strings.HasSuffix(fields[0], ".service") {
			idx = 1
		}
		if idx >= len(fields) || !strings.HasSuffix(fields[idx], ".service") {
			continue
		}

		unitName := fields[idx]
		if len(fields) <= idx+3 {
			continue
		}
		// load=fields[idx+1], active=fields[idx+2], sub=fields[idx+3]
		active := fields[idx+2]
		sub := fields[idx+3]

		description := ""
		if len(fields) > idx+4 {
			description = strings.Join(fields[idx+4:], " ")
		}

		units[unitName] = models.ServiceInfo{
			Name:        unitName,
			DisplayName: unitName,
			Status:      systemdStatus(active, sub),
			Description: description,
			Source:      "systemd",
			FirstSeenAt: now,
			UpdatedAt:   now,
		}
	}
}

// parseSystemdUnitFiles parses the `--no-legend` output of systemctl list-unit-files.
// Format: <unit-file>  <state>  [vendor-preset]
func parseSystemdUnitFiles(output []byte) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.HasSuffix(fields[0], ".service") {
			continue
		}
		result[fields[0]] = normalizeSystemdState(fields[1])
	}
	return result
}

func systemdStatus(active, sub string) string {
	switch active {
	case "active":
		if sub == "running" {
			return "running"
		}
		return "active"
	case "failed":
		return "failed"
	case "inactive":
		return "stopped"
	default:
		return strings.ToLower(active)
	}
}

func normalizeSystemdState(state string) string {
	switch state {
	case "enabled", "enabled-runtime":
		return "automatic"
	case "disabled":
		return "disabled"
	case "static":
		return "static"
	case "masked", "masked-runtime":
		return "masked"
	case "indirect":
		return "indirect"
	default:
		if state == "" {
			return "unknown"
		}
		return state
	}
}

// stripANSI removes ANSI escape sequences (color codes) from systemctl output.
func stripANSI(s string) string {
	out := strings.Builder{}
	inEscape := false
	for _, r := range s {
		switch {
		case inEscape && r == 'm':
			inEscape = false
		case inEscape:
			// inside escape sequence — skip
		case r == '\x1b':
			inEscape = true
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}
