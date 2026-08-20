//go:build linux

package osdetail

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

// errNoRebootMechanism signals that this host offers neither of the two
// pending-reboot conventions this collector knows how to check.
var errNoRebootMechanism = errors.New("osdetail: no pending-reboot mechanism available")

func platformExtra(ctx context.Context) (ex extra) {
	var sources []string

	if install, err := linuxInstallDate(ctx); err == nil {
		ex.InstallDate = install
		sources = append(sources, "best-effort:install-date")
	} else {
		ex.Warnings = append(ex.Warnings, "install date could not be determined on this host")
	}

	pending, reason, err := linuxPendingReboot(ctx)
	if err != nil {
		ex.Warnings = append(ex.Warnings, "pending-reboot could not be determined on this host")
	} else {
		p := pending
		ex.PendingReboot = &p
		ex.PendingRebootReason = reason
		sources = append(sources, "reboot-required-check")
	}

	// ActivationStatus has no Linux concept and is left empty.

	// ", " rather than "+": these hyphenated names are long enough, and
	// drawn entirely from the token/key character class, that a "+"-joined
	// run can exceed 32 characters and trip SanitizeMessage's
	// secret-shaped-token redaction — turning this harmless diagnostic
	// string into "<redacted>" in every log and CollectorResult.
	ex.Source = strings.Join(sources, ", ")
	return ex
}

// linuxInstallDate tries the Debian/Ubuntu installer marker first, then the
// earliest package install time from the RPM database. Neither is exact —
// the installer directory can be pruned, and the earliest RPM timestamp is
// whichever package happened to install first — but both are the standard,
// widely-used approximations for this on Linux. Genuinely unavailable (e.g.
// Arch, Alpine) reports an error rather than a guess.
func linuxInstallDate(ctx context.Context) (string, error) {
	if info, err := os.Stat("/var/log/installer"); err == nil {
		return info.ModTime().UTC().Format(time.RFC3339), nil
	}

	if _, err := exec.LookPath("rpm"); err == nil {
		out, _, cmdErr := shared.RunCommandOutputContext(ctx, "rpm", "-qa", "--qf", "%{installtime}\n")
		if cmdErr == nil {
			if t, ok := earliestUnixTime(out); ok {
				return time.Unix(t, 0).UTC().Format(time.RFC3339), nil
			}
		}
	}

	return "", errors.New("osdetail: no install-date source available")
}

// linuxPendingReboot prefers the Debian/Ubuntu convention when dpkg is
// present — apt and unattended-upgrades create /var/run/reboot-required
// exactly when a reboot is needed, so its absence there is a confident "no",
// not a guess. RPM-based hosts fall back to needs-restarting. A host with
// neither returns errNoRebootMechanism so the caller reports undetermined.
func linuxPendingReboot(ctx context.Context) (pending bool, reason string, err error) {
	if _, lookErr := exec.LookPath("dpkg"); lookErr == nil {
		_, statErr := os.Stat("/var/run/reboot-required")
		switch {
		case statErr == nil:
			return true, "reboot_required_file", nil
		case os.IsNotExist(statErr):
			return false, "", nil
		default:
			return false, "", statErr
		}
	}

	if _, lookErr := exec.LookPath("needs-restarting"); lookErr == nil {
		_, exitCode, cmdErr := shared.RunCommandOutputContext(ctx, "needs-restarting", "-r")
		if cmdErr != nil {
			return false, "", cmdErr
		}
		// needs-restarting -r: exit 0 = no reboot needed, exit 1 = needed.
		return exitCode == 1, "needs_restarting", nil
	}

	return false, "", errNoRebootMechanism
}
