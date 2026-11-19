// readonlycheck proves the read-only build leaves out what it must (#547).
//
// For every release target it builds the agent twice, without and with
// -tags readonly, lists both binaries' symbols with `go tool nm`, and fails
// unless each sentinel below is in the full binary and absent from the
// read-only one. Checking the full binary too keeps the check honest: a
// renamed function makes it fail instead of passing because nothing matches.
//
// Usage: go run ./scripts/readonlycheck
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// sentinel is a function only a removed feature reaches. goos limits it to
// the targets that have it (nil: all).
type sentinel struct {
	feature string
	symbol  string
	goos    []string
}

const pkg = "sentinelgo/internal/"

var sentinels = []sentinel{
	{"Scripts", pkg + "service/task.(*TaskExecutorService).runScriptTask", nil},
	{"Scripts", pkg + "service/task.(*TaskExecutorService).executeLocalScript", nil},
	{"Scripts", pkg + "service/task.(*TaskExecutorService).downloadScript", nil},
	{"DeviceActions", pkg + "service/task/native.triggerReboot", nil},
	{"DeviceActions", pkg + "service/task/native.triggerFirewallEnable", nil},
	{"DeviceActions", pkg + "service/task/native.triggerFirewallDisable", nil},
	{"DeviceActions", pkg + "localadmin.(*Manager).Apply", nil},
	{"DeviceActions", pkg + "mdmenroll.(*Unenroller).Unenroll", nil},
	{"DeviceActions", pkg + "mdmenroll.(*Syncer).Sync", nil},
	{"DeviceActions", pkg + "adminpassword.(*Rotator).Tick", []string{"windows"}},
	{"DLPEnforcement", pkg + "dlp/uploadproxy.NewService", nil},
	{"DLPEnforcement", pkg + "dlp/netctl.New", nil},
	{"DLPEnforcement", pkg + "dlp/prompt.Show", nil},
	{"YARA", pkg + "yara/ruleset.(*Syncer).Sync", nil},
	{"YARA", pkg + "yara/scan.(*Runner).StartOnDemand", nil},
	{"YARA", pkg + "dlp/scanworker.(*yaraState).compile", nil},
	{"YARA", pkg + "yara/engine.(*goYara).Compile", nil},
	{"NotifyUser", pkg + "service/task/native.(*notifyUserHandler).Run", nil},
	{"MDMEnroll", pkg + "mdmenroll.(*Enroller).Enroll", nil},
}

var targets = [][2]string{
	{"linux", "amd64"}, {"linux", "arm64"},
	{"darwin", "amd64"}, {"darwin", "arm64"},
	{"windows", "amd64"},
}

func main() {
	dir, err := os.MkdirTemp("", "readonlycheck")
	if err != nil {
		fail("%v", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	bad := 0
	for _, t := range targets {
		goos, goarch := t[0], t[1]
		full := symbols(dir, goos, goarch, "")
		ro := symbols(dir, goos, goarch, "readonly")
		for _, s := range sentinels {
			if s.goos != nil && !slices.Contains(s.goos, goos) {
				continue
			}
			if !full[s.symbol] {
				fmt.Printf("❌ %s/%s: %s isn't in the full build; update the sentinel for %s\n", goos, goarch, s.symbol, s.feature)
				bad++
			}
			if ro[s.symbol] {
				fmt.Printf("❌ %s/%s: the read-only build contains %s (%s)\n", goos, goarch, s.symbol, s.feature)
				bad++
			}
		}
		fmt.Printf("checked %s/%s\n", goos, goarch)
	}
	if bad > 0 {
		fail("%d problems", bad)
	}
	fmt.Println("✅ the read-only build leaves out scripts, device actions, DLP blocking, YARA, notify-user and mdm-enroll")
}

// symbols builds ./cmd/sentinelgo for goos/goarch with tags and returns its
// text symbols.
func symbols(dir, goos, goarch, tags string) map[string]bool {
	name := filepath.Join(dir, fmt.Sprintf("sentinelgo-%s-%s-%s", goos, goarch, tags))
	build := exec.Command("go", "build", "-trimpath", "-tags", tags, "-o", name, "./cmd/sentinelgo")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+goos, "GOARCH="+goarch)
	if out, err := build.CombinedOutput(); err != nil {
		fail("build %s/%s %q: %v\n%s", goos, goarch, tags, err, out)
	}
	out, err := exec.Command("go", "tool", "nm", name).Output()
	if err != nil {
		fail("nm %s: %v", name, err)
	}
	syms := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 3 && (f[len(f)-2] == "T" || f[len(f)-2] == "t") {
			syms[f[len(f)-1]] = true
		}
	}
	return syms
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "readonlycheck: "+format+"\n", a...)
	os.Exit(1)
}
