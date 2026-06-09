package printers

import (
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

func getPrinters() []shared.Printer {
	var printers []shared.Printer
	seen := make(map[string]bool)

	if output, err := shared.RunCommand("lpstat", "-p"); err == nil {
		printers = append(printers, parseLpstat(output, seen)...)
	}

	if output, err := shared.RunCommand("system_profiler", "SPPrintersDataType"); err == nil {
		var currentPrinter string
		for _, line := range strings.Split(output, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Name:") {
				currentPrinter = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
			} else if strings.HasPrefix(line, "Type:") && currentPrinter != "" && !seen[currentPrinter] {
				printingType := strings.TrimSpace(strings.TrimPrefix(line, "Type:"))
				if printingType == "" {
					printingType = "Colorful"
				}
				printers = append(printers, newPrinter(currentPrinter, printingType, 0, 0))
				seen[currentPrinter] = true
				currentPrinter = ""
			}
		}
	}

	return printers
}
