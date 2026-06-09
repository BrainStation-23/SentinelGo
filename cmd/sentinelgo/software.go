package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"sentinelgo/internal/config"
	"sentinelgo/internal/sanitize"
	swsvc "sentinelgo/internal/service/software"
)

func showSoftwareList(softwareList []swsvc.SoftwareInfo) {
	fmt.Printf("Found %d installed software items:\n\n", len(softwareList))

	byType := make(map[string][]swsvc.SoftwareInfo)
	for _, sw := range softwareList {
		byType[sw.Type] = append(byType[sw.Type], sw)
	}

	for typeName, items := range byType {
		fmt.Printf("=== %s (%d items) ===\n", sanitize.ForLog(strings.ToUpper(typeName)), len(items))
		for i, sw := range items {
			fmt.Printf("%d. %s\n", i+1, sanitize.ForLog(sw.Name))
			fmt.Printf("   Version: %s\n", sanitize.ForLog(sw.InstalledVersion))
			fmt.Printf("   Source: %s\n", sanitize.ForLog(sw.Source))
			if sw.DisplayName != "" && sw.DisplayName != sw.Name {
				fmt.Printf("   Display: %s\n", sanitize.ForLog(sw.DisplayName))
			}
			if sw.FilePath != "" {
				fmt.Printf("   Path: %s\n", sanitize.ForLog(sw.FilePath))
			}
			if sw.Status != "" {
				fmt.Printf("   Status: %s\n", sanitize.ForLog(sw.Status))
			}
			fmt.Printf("   Active: %t\n", sw.IsActive)
			if sw.FirstSeenAt != "" {
				fmt.Printf("   First Seen: %s\n", sanitize.ForLog(sw.FirstSeenAt))
			}
			if sw.LastSeenAt != "" {
				fmt.Printf("   Last Seen: %s\n", sanitize.ForLog(sw.LastSeenAt))
			}
			fmt.Println()
		}
		fmt.Println()
	}
}

func outputSoftwareJSON(softwareList []swsvc.SoftwareInfo) {
	jsonData, err := json.MarshalIndent(softwareList, "", "  ")
	if err != nil {
		log.Printf("Error marshaling to JSON: %v", err)
		os.Exit(1)
	}
	fmt.Println(string(jsonData))
}

// handleSoftwareSync runs the software sync service until interrupted.
func handleSoftwareSync(cfg *config.Config) {
	if !cfg.SoftwareSyncEnabled {
		fmt.Println("Software sync is disabled. Enable with software_sync_enabled in config")
		return
	}

	fmt.Println("Starting software sync service...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	softwareService := swsvc.NewSoftwareService()
	softwareService.SetSupabaseURL(cfg.SupabaseURL)
	if cfg.EdgeFunctionURL != "" {
		softwareService.SetEdgeFunctionConfig(cfg.EdgeFunctionURL, cfg.AccessToken)
	}

	go func() {
		if err := softwareService.StartSoftwareSync(ctx, cfg, softwareService.GetSoftwareList); err != nil {
			log.Printf("Software sync error: %v", err)
		}
	}()

	<-sigChan
	cancel()
	fmt.Println("Software sync service stopped")
}

// handleSoftwareListCommand collects installed software and prints it as a list,
// JSON, or count depending on the flags.
func handleSoftwareListCommand(cfgPath string, asJSON, countOnly bool) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Printf("Warning: Could not load config: %v", err)
		cfg = &config.Config{}
	}

	sw := swsvc.NewSoftwareService()

	if cfg.SoftwareSyncEnabled && cfg.EdgeFunctionURL != "" && cfg.AccessToken != "" {
		sw.SetEdgeFunctionConfig(cfg.EdgeFunctionURL, cfg.AccessToken)
	}

	swList := sw.GetSoftwareList()

	switch {
	case asJSON:
		outputSoftwareJSON(swList)
	case countOnly:
		fmt.Printf("Total software items: %d\n", len(swList))
	default:
		showSoftwareList(swList)
	}
}
