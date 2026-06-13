package printers

import (
	"encoding/json"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

func getPrinters() []shared.Printer {
	var printers []shared.Printer
	seen := make(map[string]bool)

	if output, err := shared.RunCommand("powershell", "-NoProfile", "-Command",
		"Get-Printer | Select-Object Name, DriverName, Type | ConvertTo-Json -Depth 2"); err == nil {
		printers = append(printers, parseWindowsPrinterJSON(output, seen)...)
	}

	if len(printers) == 0 {
		if output, err := shared.RunCommand("wmic", "printer", "list", "brief"); err == nil {
			printers = append(printers, parseWMICPrinterOutput(output, seen)...)
		}
	}

	return printers
}

func parseWindowsPrinterJSON(output string, seen map[string]bool) []shared.Printer {
	var arr []map[string]any
	var obj map[string]any
	if json.Unmarshal([]byte(output), &arr) != nil {
		if json.Unmarshal([]byte(output), &obj) == nil {
			arr = []map[string]any{obj}
		}
	}
	var printers []shared.Printer
	for _, item := range arr {
		name, ok := item["Name"].(string)
		if !ok || seen[name] {
			continue
		}
		driverName, _ := item["DriverName"].(string)
		dl := strings.ToLower(driverName)
		printingType := "Colorful"
		if strings.Contains(dl, "laser") || strings.Contains(dl, "mono") {
			printingType = "Black and white"
		}
		hDPI, vDPI := 0, 0
		switch {
		case strings.Contains(dl, "1200"):
			hDPI, vDPI = 1200, 1200
		case strings.Contains(dl, "600"):
			hDPI, vDPI = 600, 600
		case strings.Contains(dl, "360"):
			hDPI, vDPI = 360, 360
		}
		printers = append(printers, newPrinter(name, printingType, hDPI, vDPI))
		seen[name] = true
	}
	return printers
}

func parseWMICPrinterOutput(output string, seen map[string]bool) []shared.Printer {
	var printers []shared.Printer
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.Contains(line, "Name") || strings.Contains(line, "===") {
			continue
		}
		parts := strings.Split(line, "  ")
		if len(parts) > 0 && parts[0] != "" && !seen[parts[0]] {
			printers = append(printers, newPrinter(parts[0], "Colorful", 0, 0))
			seen[parts[0]] = true
		}
	}
	return printers
}
