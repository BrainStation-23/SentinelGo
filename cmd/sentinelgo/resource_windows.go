//go:build windows

package main

// Embed the SentinelGo icon and version metadata into the Windows binary.
// Running `go generate` (or `make generate`) invokes goversioninfo to produce
// resource.syso, which the Go linker picks up automatically for GOOS=windows.
//
// Install goversioninfo once:
//   go install github.com/josephspurrier/goversioninfo/cmd/goversioninfo@v1.4.1
//
// Then regenerate after bumping the version in assets/resource.json:
//   go generate ./cmd/sentinelgo
//
//go:generate goversioninfo -64 -icon=../../assets/icons/sentinelgo.ico -manifest=../../assets/sentinelgo.exe.manifest -o resource_windows.syso ../../assets/resource.json
