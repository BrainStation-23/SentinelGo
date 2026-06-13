package printers

import (
	"os"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

func getPrinters() []shared.Printer {
	var printers []shared.Printer
	seen := make(map[string]bool)

	if output, err := shared.RunCommand("lpstat", "-p"); err == nil {
		printers = append(printers, parseLpstat(output, seen)...)
	}

	if content, err := os.ReadFile("/etc/cups/printers.conf"); err == nil {
		printers = append(printers, parseCupsPrintersConf(string(content), seen)...)
	}

	return printers
}

func parseCupsPrintersConf(content string, seen map[string]bool) []shared.Printer {
	var printers []shared.Printer
	var currentPrinter string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "<Printer ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentPrinter = strings.Trim(parts[1], ">")
			}
		} else if strings.HasPrefix(line, "DeviceURI") && currentPrinter != "" && !seen[currentPrinter] {
			printers = append(printers, newPrinter(currentPrinter, "Colorful", 0, 0))
			seen[currentPrinter] = true
		}
	}
	return printers
}
