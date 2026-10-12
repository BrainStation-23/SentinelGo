package main

import (
	"fmt"
	"runtime"
	"strings"

	"sentinelgo/internal/config"
	"sentinelgo/internal/constants"
)

// Version is injected at build time via -ldflags. Falls back to config.Version if empty.
var Version string

func GetVersion() string {
	if Version != "" {
		return Version
	}
	return config.Version
}

// printVersion prints version and build information.
func printVersion() {
	fmt.Printf("SentinelGo version: %s\n", Version)
	fmt.Printf("Build info: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Capabilities: %s\n", strings.Join(constants.Capabilities(), ", "))
}
