//go:build windows

package notify

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// The AUMID must be our own app ID, not Windows PowerShell's.
func TestCommand_SentinelGoAUMID(t *testing.T) {
	cmd := command(context.Background(), "t", "b", "")
	if strings.Contains(strings.Join(cmd.Args, " "), `1AC14E77-02E7-4E5D-B744-2EB1AE5198B7`) {
		t.Error("command still uses the old PowerShell AUMID; switch to SentinelGo AUMID")
	}
	if !slices.Contains(cmd.Env, "SG_NOTIFY_AUMID="+sentinelGoAUMID) {
		t.Errorf("SG_NOTIFY_AUMID not set in env; got %v", cmd.Env)
	}
}

// The script must use ToastGeneric (not the legacy ToastText02 template) so
// notifications persist in the Action Center.
func TestToastScript_UsesGenericTemplate(t *testing.T) {
	if strings.Contains(toastScript, "ToastText02") {
		t.Error("toastScript still uses legacy ToastText02; switch to ToastGeneric")
	}
	if !strings.Contains(toastScript, "ToastGeneric") {
		t.Error("toastScript does not use ToastGeneric template")
	}
}
