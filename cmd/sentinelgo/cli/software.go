package cli

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
			if sw.FirstSeenAt != "" {
				fmt.Printf("   Install Date: %s\n", sanitize.ForLog(sw.FirstSeenAt))
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
		return
	}
	fmt.Println(string(jsonData))
}

// HandleSoftwareSync collects installed software and sends it to Supabase once.
func HandleSoftwareSync(cfg *config.Config) {
	if !cfg.SoftwareSyncEnabled {
		fmt.Println("Software sync is disabled. Enable with software_sync_enabled in config")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	go func() {
		<-sigChan
		cancel()
	}()

	svc := swsvc.NewSoftwareService()
	svc.SetSupabaseURL(cfg.SupabaseURL)

	list, complete := svc.GetSoftwareListWithStatus()
	if len(list) == 0 {
		fmt.Println("No software found.")
		return
	}
	fmt.Printf("Collected %d software items. Sending...\n", len(list))
	if err := svc.SendSnapshotByRPC(ctx, list, complete, cfg); err != nil {
		log.Printf("Software sync error: %v", err)
		return
	}
	fmt.Println("Software sync complete.")
}

// HandleSoftwareListCommand collects installed software and prints it as a list,
// JSON, or count depending on the flags.
func HandleSoftwareListCommand(_ string, asJSON, countOnly bool) {
	sw := swsvc.NewSoftwareService()
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
