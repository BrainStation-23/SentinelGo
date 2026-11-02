package mdmenroll

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"sentinelgo/internal/binpath"
)

// startSession starts an OMA-DM session for an enrollment the way its own
// scheduled tasks do (deviceenroller /o <id> /c /b). If that fails, it runs
// the enrollment's PushLaunch task. Windows documents no API for this.
var startSession = func(ctx context.Context, enrollmentID string) error {
	if !validEnrollmentID(enrollmentID) {
		return fmt.Errorf("unexpected enrollment ID %q", enrollmentID)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err := runTool(ctx, "deviceenroller", "/o", enrollmentID, "/c", "/b")
	if err == nil {
		return nil
	}
	task := `\Microsoft\Windows\EnterpriseMgmt\` + enrollmentID + `\PushLaunch`
	if err2 := runTool(ctx, "schtasks", "/Run", "/TN", task); err2 != nil {
		return fmt.Errorf("deviceenroller: %v; PushLaunch task: %v", err, err2)
	}
	return nil
}

func runTool(ctx context.Context, name string, args ...string) error {
	path, ok := binpath.Lookup(name)
	if !ok {
		return fmt.Errorf("%s not found", name)
	}
	out, err := exec.CommandContext(ctx, path, args...).CombinedOutput() // #nosec G204 -- fixed System32 tool; the ID is validated
	if err != nil {
		return fmt.Errorf("%v: %s", err, firstLine(string(out)))
	}
	return nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
