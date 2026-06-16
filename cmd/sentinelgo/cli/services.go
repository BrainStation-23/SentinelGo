package cli

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
	"sentinelgo/internal/sanitize"
	servicessvc "sentinelgo/internal/service/services"
)

// HandleServicesListCommand collects running OS services and prints them as a
// table, JSON array, or count depending on the flags.
func HandleServicesListCommand(cfgPath string, asJSON, countOnly bool) {
	_, err := config.Load(cfgPath)
	if err != nil {
		log.Printf("Warning: Could not load config: %v", err)
	}

	svc := servicessvc.NewServicesService()
	list := svc.GetServiceList()

	switch {
	case asJSON:
		outputServicesJSON(list)
	case countOnly:
		fmt.Printf("Total services: %d\n", len(list))
	default:
		showServicesList(list)
	}
}

func showServicesList(svcs []models.ServiceInfo) {
	fmt.Printf("Found %d services:\n\n", len(svcs))

	bySource := make(map[string][]models.ServiceInfo)
	for _, svc := range svcs {
		bySource[svc.Source] = append(bySource[svc.Source], svc)
	}

	for source, items := range bySource {
		fmt.Printf("=== %s (%d items) ===\n", sanitize.ForLog(strings.ToUpper(source)), len(items))
		for i, svc := range items {
			printServiceItem(i+1, svc)
		}
		fmt.Println()
	}
}

func printServiceItem(n int, svc models.ServiceInfo) {
	fmt.Printf("%d. %s\n", n, sanitize.ForLog(svc.Name))
	if svc.DisplayName != "" && svc.DisplayName != svc.Name {
		fmt.Printf("   Display: %s\n", sanitize.ForLog(svc.DisplayName))
	}
	fmt.Printf("   Status: %s\n", sanitize.ForLog(svc.Status))
	fmt.Printf("   Start: %s\n", sanitize.ForLog(svc.StartType))
	if svc.Description != "" {
		fmt.Printf("   Desc: %s\n", sanitize.ForLog(svc.Description))
	}
	if svc.PID > 0 {
		fmt.Printf("   PID: %d\n", svc.PID)
	}
	if svc.RunAs != "" {
		fmt.Printf("   RunAs: %s\n", sanitize.ForLog(svc.RunAs))
	}
	fmt.Println()
}

func outputServicesJSON(svcs []models.ServiceInfo) {
	data, err := json.MarshalIndent(svcs, "", "  ")
	if err != nil {
		log.Printf("Error marshaling services to JSON: %v", err)
		return
	}
	fmt.Println(string(data))
}
