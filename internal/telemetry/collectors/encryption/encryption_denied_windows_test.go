//go:build windows

package encryption

import (
	"errors"
	"os/exec"
	"strings"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

// These tests cover a distinction found during real validation on a Windows
// host: running the agent without elevation made Get-BitLockerVolume fail with
// CimException "Access denied", and the collector reported it as a generic
// `error (exit_status:1)`. Both statuses count as a collector failure, so
// telemetry health was already correct — what was missing was the operator
// being able to tell "give the agent rights" from "something broke".

// exitWith runs a real process that exits with the given code, producing a
// genuine *exec.ExitError. Synthesising one by hand is not possible without a
// real os.ProcessState.
func exitWith(t *testing.T, code int) error {
	t.Helper()
	err := exec.Command("cmd", "/c", "exit", string(rune('0'+code))).Run()
	if err == nil {
		t.Fatalf("cmd /c exit %d returned no error", code)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected *exec.ExitError, got %T", err)
	}
	if exitErr.ExitCode() != code {
		t.Fatalf("exit code = %d, want %d", exitErr.ExitCode(), code)
	}
	return err
}

// TestAccessDeniedMapsToPermissionDenied is the regression test. The script
// signals a rights failure with exit code 2, and that must reach the wire as
// permission_denied rather than a generic error.
func TestAccessDeniedMapsToPermissionDenied(t *testing.T) {
	sig := classifyRunError(exitWith(t, exitAccessDenied))

	status, reason := tel.SanitizeError(sig.Err)
	if status != tel.StatusPermissionDenied {
		t.Errorf("status = %q, want %q — an agent without rights must be told to "+
			"get rights, not that something broke", status, tel.StatusPermissionDenied)
	}
	if reason != tel.ReasonPermissionDenied {
		t.Errorf("reason = %q, want %q", reason, tel.ReasonPermissionDenied)
	}
	if len(sig.Volumes) != 0 {
		t.Error("a denied read reported volumes; it must never claim the disk is " +
			"unencrypted when it could not look")
	}
}

// TestOtherFailuresStayGenericErrors pins that the new branch did not swallow
// every failure into permission_denied.
func TestOtherFailuresStayGenericErrors(t *testing.T) {
	sig := classifyRunError(exitWith(t, exitQueryFailed))

	status, _ := tel.SanitizeError(sig.Err)
	if status == tel.StatusPermissionDenied {
		t.Error("a generic script failure was reported as permission_denied")
	}
	if status != tel.StatusError {
		t.Errorf("status = %q, want %q", status, tel.StatusError)
	}
}

// TestExitCodesAreDistinct guards the contract between the PowerShell script
// and the Go side. If these ever collide, every failure silently becomes
// whichever branch is checked first.
func TestExitCodesAreDistinct(t *testing.T) {
	if exitAccessDenied == exitQueryFailed {
		t.Fatal("the access-denied and generic-failure exit codes are the same")
	}
}

// TestScriptDetectsAccessDeniedLocaleIndependently pins the mechanism.
//
// NativeErrorCode is an enum NAME, so it reads the same on any Windows
// language. The alternatives were checked against a real denial on a live host
// and do not work: Exception.HResult is the generic 0x80131500
// (COR_E_EXCEPTION), not E_ACCESSDENIED, and matching the message text would
// break on any non-English install.
func TestScriptDetectsAccessDeniedLocaleIndependently(t *testing.T) {
	if !strings.Contains(bitlockerVolumeScript, "NativeErrorCode") {
		t.Error("the script no longer reads NativeErrorCode, so access denied " +
			"cannot be told apart from any other failure")
	}
	if !strings.Contains(bitlockerVolumeScript, "AccessDenied") {
		t.Error("the script no longer matches the AccessDenied enum name")
	}
	for _, fragile := range []string{"Access denied", "-match", "HResult"} {
		if strings.Contains(bitlockerVolumeScript, fragile) {
			t.Errorf("the script detects access denial via %q, which is locale- or "+
				"HResult-dependent and was verified not to work", fragile)
		}
	}
}

// TestDeniedWarningCarriesNoCommandOutput pins the sanitisation rule: the
// warning explains the condition without echoing anything the command printed.
func TestDeniedWarningCarriesNoCommandOutput(t *testing.T) {
	sig := classifyRunError(exitWith(t, exitAccessDenied))

	if len(sig.Warnings) == 0 {
		t.Fatal("a denied read produced no warning")
	}
	for _, w := range sig.Warnings {
		if clean := tel.SanitizeMessage(w); clean != w {
			t.Errorf("warning is altered by sanitisation:\n  in:  %q\n  out: %q", w, clean)
		}
	}
}
