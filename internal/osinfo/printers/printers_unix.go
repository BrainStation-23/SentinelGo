//go:build linux || darwin

package printers

import (
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// parseLpstat parses `lpstat -p` output and appends new printers into seen.
func parseLpstat(output string, seen map[string]bool) []shared.Printer {
	var result []shared.Printer
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "printer ") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		name := parts[1]
		if seen[name] {
			continue
		}
		printingType := "Colorful"
		nl := strings.ToLower(name)
		if strings.Contains(nl, "laser") || strings.Contains(nl, "mono") {
			printingType = "Black and white"
		}
		result = append(result, newPrinter(name, printingType, 0, 0))
		seen[name] = true
	}
	return result
}
