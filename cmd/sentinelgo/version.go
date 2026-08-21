package main

import (
	"fmt"
	"runtime"

	"sentinelgo/internal/config"
	"sentinelgo/internal/version"
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
//
// A development build says so on its own line rather than printing a bare
// version string. The string it would print — "v3.2.6-4-g40f52e7-dirty" — looks
// enough like a release to be pasted into a bug report as one, and its base tag
// can name an older release than the machine is actually running (see
// internal/version). Making the classification explicit here means nobody has
// to recognise the shape of git-describe output to know what they are looking
// at.
func printVersion() {
	fmt.Printf("SentinelGo version: %s\n", GetVersion())
	fmt.Printf("Build info: %s/%s\n", runtime.GOOS, runtime.GOARCH)

	info := version.Parse(GetVersion())
	if info.IsRelease() {
		fmt.Println("Build type: release")
		return
	}

	fmt.Printf("Build type: development (%s)\n", info.Reason)
	if info.Semver != "" {
		fmt.Printf("Nearest reachable tag: %s\n", info.Semver)
	}
	fmt.Println("Note: development builds do not self-update.")
}
