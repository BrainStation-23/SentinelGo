//go:build windows

package encryption

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"strings"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// bitlockerVolumeScript reports MountPoint, ProtectionStatus,
// EncryptionPercentage, and a flattened list of key protector type names —
// the exact fields the matrix doc calls out (ProtectionStatus,
// EncryptionPercentage, EncryptionMethod, key protector types).
//
// $ErrorActionPreference = 'Stop' plus the try/catch is load-bearing, not
// decoration: the BitLocker module's underlying Get-CimInstance call signals
// "access denied" (confirmed by hand: this cmdlet requires elevation and
// fails when the agent is not running with sufficient rights) via a
// NON-terminating Write-Error, which by default leaves the script's exit
// code at 0. shared.RunCommand only inspects the exit code and stdout — it
// cannot see that non-terminating error at all — so without forcing it
// terminating here, a permission failure would silently produce empty stdout
// and be reported as "success, zero encrypted volumes" instead of a genuine
// failure. This is exactly the silently-wrong-answer class of bug the
// directory collector's review caught for a different mechanism.
const bitlockerVolumeScript = `$ErrorActionPreference = 'Stop'
try {
	Get-BitLockerVolume | ForEach-Object {
		[PSCustomObject]@{
			MountPoint = ''+$_.MountPoint
			ProtectionStatus = ''+$_.ProtectionStatus.ToString()
			EncryptionPercentage = $_.EncryptionPercentage
			KeyProtectorTypes = @($_.KeyProtector | ForEach-Object { ''+$_.KeyProtectorType.ToString() })
		}
	} | ConvertTo-Json -Compress -Depth 4
} catch {
	$code = ''
	try { $code = ''+$_.Exception.NativeErrorCode } catch {}
	if ($code -eq 'AccessDenied') { exit 2 }
	exit 1
}`

// Exit codes returned by bitlockerVolumeScript.
//
// The split exists so an agent that lacks rights is reported as
// permission_denied — actionable, "give it elevation" — rather than as a
// generic error that says only "something broke". Both statuses count as a
// collector failure, so telemetry health is unaffected; what changes is whether
// an operator can tell which failure they have.
//
// AccessDenied is matched on CimException.NativeErrorCode, which is an enum
// NAME and therefore locale-independent. The obvious alternatives were checked
// on a real host and do not work: HResult is the generic 0x80131500
// (COR_E_EXCEPTION), not E_ACCESSDENIED, and matching the message text
// ("Access denied") would break on any non-English Windows.
const (
	exitQueryFailed  = 1
	exitAccessDenied = 2
)

// platformCapability checks whether the BitLocker PowerShell module is
// present: it ships with Pro/Enterprise/Education editions but not Home, so
// this is a real, worth-checking gate rather than an always-true one.
func platformCapability(_ context.Context) tel.CapabilityState {
	out, err := shared.RunCommand("powershell", "-NoProfile", "-Command",
		"if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) { 'yes' } else { 'no' }")
	if err != nil || strings.TrimSpace(out) != "yes" {
		return tel.CapUnsupported
	}
	return tel.CapSupported
}

// classifyRunError turns a failed script run into a signal, distinguishing a
// rights problem from everything else.
//
// Split out from platformVolumes so the mapping is testable without a machine
// that actually denies access — the branch that matters most is the one hardest
// to reproduce on demand.
//
// shared.RunCommand uses cmd.Output(), so a non-zero exit arrives as an
// *exec.ExitError carrying the script's own code. Reading it here rather than
// switching to the combined-output helper keeps stdout clean: the script's JSON
// must not be interleaved with anything PowerShell writes to stderr.
func classifyRunError(err error) signal {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == exitAccessDenied {
		return signal{
			Warnings: []string{"Get-BitLockerVolume denied: the agent lacks the rights to read BitLocker state"},
			// fs.ErrPermission is what telemetry.SanitizeError maps to
			// StatusPermissionDenied; wrapping preserves the cause without
			// putting any command output on the wire.
			Err: fmt.Errorf("read BitLocker volumes: %w", fs.ErrPermission),
		}
	}
	return signal{Warnings: []string{"Get-BitLockerVolume query failed"}, Err: err}
}

func platformVolumes(_ context.Context) signal {
	out, err := shared.RunCommand("powershell", "-NoProfile", "-Command", bitlockerVolumeScript)
	if err != nil {
		return classifyRunError(err)
	}

	rows, parseErr := parseWindowsVolumes(out)
	if parseErr != nil {
		return signal{Warnings: []string{"Get-BitLockerVolume returned unparseable JSON"}, Err: parseErr}
	}

	volumes := make([]Volume, 0, len(rows))
	for _, r := range rows {
		volumes = append(volumes, r.toVolume())
	}

	return signal{Volumes: volumes, Source: "powershell:Get-BitLockerVolume"}
}
