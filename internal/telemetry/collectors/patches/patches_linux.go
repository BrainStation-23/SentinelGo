//go:build linux

package patches

import (
	"context"
	"os/exec"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

func platformUpdates(ctx context.Context) signal {
	var updates []Update
	var warnings []string
	var sources []string

	switch {
	case commandExists("dpkg"):
		if out, err := shared.ReadFileContent("/var/log/dpkg.log"); err == nil {
			updates = append(updates, parseDpkgLog(out)...)
			sources = append(sources, "file:/var/log/dpkg.log")
		} else {
			warnings = append(warnings, "dpkg.log unreadable")
		}

		if commandExists("apt") {
			out, _, err := shared.RunCommandOutputContext(ctx, "apt", "list", "--upgradable")
			if err != nil {
				warnings = append(warnings, "apt list --upgradable failed to run")
			} else {
				updates = append(updates, parseAptUpgradable(out)...)
				sources = append(sources, "exec:apt")
			}
		}

	case commandExists("rpm"):
		out, _, err := shared.RunCommandOutputContext(ctx, "rpm", "-qa", "--last")
		if err != nil {
			warnings = append(warnings, "rpm -qa --last failed to run")
		} else {
			updates = append(updates, parseRpmLast(out)...)
			sources = append(sources, "exec:rpm")
		}

		checker := ""
		switch {
		case commandExists("dnf"):
			checker = "dnf"
		case commandExists("yum"):
			checker = "yum"
		}
		if checker != "" {
			// dnf/yum check-update signals "updates available" via exit code
			// 100, not a failure — RunCommandOutputContext is required here
			// for exactly the reason its own doc comment states: a
			// non-zero-but-meaningful exit must not discard the output.
			out, exitCode, cmdErr := shared.RunCommandOutputContext(ctx, checker, "check-update")
			if cmdErr != nil {
				warnings = append(warnings, checker+" check-update failed to run")
			} else if exitCode == 0 || exitCode == 100 {
				updates = append(updates, parseCheckUpdate(out)...)
				sources = append(sources, "exec:"+checker)
			} else {
				warnings = append(warnings, checker+" check-update returned an unexpected exit code")
			}
		}

	default:
		warnings = append(warnings, "no supported package manager found (dpkg, rpm)")
	}

	return signal{Updates: updates, Source: strings.Join(sources, ", "), Warnings: warnings}
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
