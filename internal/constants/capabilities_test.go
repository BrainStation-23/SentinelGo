//go:build !readonly

package constants

import (
	"regexp"
	"slices"
	"testing"

	"sentinelgo/internal/yara"
)

func TestAgentCapabilities_Valid(t *testing.T) {
	re := regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	seen := map[string]bool{}
	for _, c := range AgentCapabilities {
		if !re.MatchString(c) {
			t.Errorf("capability %q does not match %s", c, re)
		}
		if seen[c] {
			t.Errorf("capability %q listed twice", c)
		}
		seen[c] = true
	}
}

func TestCapabilities_ReturnsCopy(t *testing.T) {
	got := Capabilities()
	got[0] = "changed"
	if AgentCapabilities[0] == "changed" {
		t.Error("Capabilities() returned the shared slice")
	}
}

func TestCapabilityScriptPwsh_Valid(t *testing.T) {
	re := regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	if !re.MatchString(CapabilityScriptPwsh) {
		t.Errorf("capability %q does not match %s", CapabilityScriptPwsh, re)
	}
	for _, c := range AgentCapabilities {
		if c == CapabilityScriptPwsh {
			t.Errorf("%q must not be in the static list: it depends on the device", c)
		}
	}
}

func TestCapabilities_PwshDependsOnDevice(t *testing.T) {
	orig := pwshInstalled
	t.Cleanup(func() { pwshInstalled = orig })

	for _, installed := range []bool{true, false} {
		pwshInstalled = func() bool { return installed }
		got := Capabilities()
		if has := slices.Contains(got, CapabilityScriptPwsh); has != installed {
			t.Errorf("pwsh installed=%v: Capabilities() = %q, contains %s = %v", installed, got, CapabilityScriptPwsh, has)
		}
		if !slices.Equal(got[:len(AgentCapabilities)], AgentCapabilities) {
			t.Errorf("Capabilities() = %q, want the static list first", got)
		}
	}
}

// documentedCapabilities is what the full build advertises on each OS
// without pwsh: every entry is one the server checks (#563). Changing what
// the agent advertises means changing this list and the comment next to the
// capability, in the same change.
var documentedCapabilities = map[string][]string{
	"linux": {
		"script_inline_body_v1", "task_artifacts_v1", "desktop_notify_v1", "dlp_warn_v1",
		"packages_v1", "yara_scan_v1", "yara_on_write_v1", "yara_scan_report_v1",
	},
	"darwin": {
		"script_inline_body_v1", "task_artifacts_v1", "desktop_notify_v1", "dlp_warn_v1",
		"packages_v1", "yara_scan_v1", "yara_on_write_v1", "yara_scan_report_v1",
		"mdm_enroll_v1",
	},
	"windows": {
		"script_inline_body_v1", "task_artifacts_v1", "desktop_notify_v1", "dlp_warn_v1",
		"packages_v1", "yara_scan_v1", "yara_on_write_v1", "yara_scan_report_v1",
		"mdm_sync_v1", "mdm_enroll_v1", "mdm_unenroll_v1", "admin_password_rotation_v1", "dlp_network_control_v1",
	},
}

func TestCapabilities_MatchDocumentedList(t *testing.T) {
	defer func(g string, p func() bool) { goos, pwshInstalled = g, p }(goos, pwshInstalled)
	pwshInstalled = func() bool { return false }
	for os, want := range documentedCapabilities {
		goos = os
		if got := Capabilities(); !slices.Equal(got, want) {
			t.Errorf("%s: Capabilities() = %q, want %q", os, got, want)
		}
	}
}

// A retired capability name is never advertised again (#563).
func TestRetiredCapabilities_NeverAdvertised(t *testing.T) {
	defer func(g string, p func() bool) { goos, pwshInstalled = g, p }(goos, pwshInstalled)
	pwshInstalled = func() bool { return true }
	for _, os := range []string{"linux", "darwin", "windows"} {
		goos = os
		for _, c := range Capabilities() {
			if slices.Contains(RetiredCapabilities, c) {
				t.Errorf("%s advertises retired capability %q", os, c)
			}
		}
	}
	for _, c := range []string{CapabilityScriptPwsh, CapabilityMDMEnroll, CapabilityMDMSync, CapabilityMDMUnenroll,
		CapabilityAdminPasswordRotation, CapabilityDLPNetworkControl} {
		if slices.Contains(RetiredCapabilities, c) {
			t.Errorf("constant %q reuses a retired name", c)
		}
	}
}

// mdm_sync_v1 is advertised on Windows only (#357).
func TestCapabilities_MDMSyncOnWindowsOnly(t *testing.T) {
	prev := goos
	t.Cleanup(func() { goos = prev })
	for os, want := range map[string]bool{"windows": true, "darwin": false, "linux": false} {
		goos = os
		if got := slices.Contains(Capabilities(), CapabilityMDMSync); got != want {
			t.Errorf("%s: mdm_sync_v1 advertised = %v, want %v", os, got, want)
		}
	}
}

// mdm-enroll runs on macOS and Windows; mdm-unenroll on Windows (#356).
func TestCapabilities_MDMTasks(t *testing.T) {
	prev := goos
	t.Cleanup(func() { goos = prev })
	for os, want := range map[string][2]bool{"darwin": {true, false}, "windows": {true, true}, "linux": {false, false}} {
		goos = os
		caps := Capabilities()
		enroll, unenroll := slices.Contains(caps, CapabilityMDMEnroll), slices.Contains(caps, CapabilityMDMUnenroll)
		if enroll != want[0] || unenroll != want[1] {
			t.Errorf("%s: enroll/unenroll = %v/%v, want %v", os, enroll, unenroll, want)
		}
	}
}

// yara_on_write_v1 is advertised on every OS: the watchers (fanotify,
// ReadDirectoryChangesW, FSEvents) and the on-write pipeline ship in this
// binary (#418). The backend sends an enabled on_write block only to agents
// that report it (contract v1.1).
func TestCapabilities_YARAOnWrite(t *testing.T) {
	if yara.CapabilityOnWrite != "yara_on_write_v1" || !slices.Contains(AgentCapabilities, yara.CapabilityOnWrite) {
		t.Fatalf("%s not in AgentCapabilities %q", yara.CapabilityOnWrite, AgentCapabilities)
	}
	prev := goos
	t.Cleanup(func() { goos = prev })
	for _, os := range []string{"windows", "darwin", "linux"} {
		goos = os
		if !slices.Contains(Capabilities(), yara.CapabilityOnWrite) {
			t.Errorf("%s: yara_on_write_v1 not advertised", os)
		}
	}
}

// yara_scan_v1 is advertised on every OS since scans work end to end (sync,
// workers, walk, events, tasks: #416). The backend sends rules and yara-scan
// tasks only to agents that report it.
func TestCapabilities_YARAScan(t *testing.T) {
	if yara.Capability != "yara_scan_v1" || !slices.Contains(AgentCapabilities, yara.Capability) {
		t.Fatalf("%s not in AgentCapabilities %q", yara.Capability, AgentCapabilities)
	}
	prev := goos
	t.Cleanup(func() { goos = prev })
	for _, os := range []string{"windows", "darwin", "linux"} {
		goos = os
		if !slices.Contains(Capabilities(), yara.Capability) {
			t.Errorf("%s: yara_scan_v1 not advertised", os)
		}
	}
}

// yara_scan_report_v1 is advertised on every OS: the contract v1.2 report
// fields come from the walk and the runner, which are the same everywhere.
func TestCapabilities_YARAScanReport(t *testing.T) {
	if yara.CapabilityScanReport != "yara_scan_report_v1" || !slices.Contains(AgentCapabilities, yara.CapabilityScanReport) {
		t.Fatalf("%s not in AgentCapabilities %q", yara.CapabilityScanReport, AgentCapabilities)
	}
	prev := goos
	t.Cleanup(func() { goos = prev })
	for _, os := range []string{"windows", "darwin", "linux"} {
		goos = os
		if !slices.Contains(Capabilities(), yara.CapabilityScanReport) {
			t.Errorf("%s: yara_scan_report_v1 not advertised", os)
		}
	}
}

// admin_password_rotation_v1 is advertised on Windows only (#361).
func TestCapabilities_AdminPasswordRotationOnWindowsOnly(t *testing.T) {
	prev := goos
	t.Cleanup(func() { goos = prev })
	for os, want := range map[string]bool{"windows": true, "darwin": false, "linux": false} {
		goos = os
		if got := slices.Contains(Capabilities(), CapabilityAdminPasswordRotation); got != want {
			t.Errorf("%s: admin_password_rotation_v1 advertised = %v, want %v", os, got, want)
		}
	}
}

// dlp_network_control_v1 is advertised on Windows only (#427): only WFP
// applies the network controls.
func TestCapabilities_DLPNetworkControlOnWindowsOnly(t *testing.T) {
	prev := goos
	t.Cleanup(func() { goos = prev })
	for os, want := range map[string]bool{"windows": true, "darwin": false, "linux": false} {
		goos = os
		if got := slices.Contains(Capabilities(), CapabilityDLPNetworkControl); got != want {
			t.Errorf("%s: dlp_network_control_v1 advertised = %v, want %v", os, got, want)
		}
	}
}

// Every capability the read-only build drops is one the full build has
// somewhere, so a typo or a rename can't leave one advertised (#547).
func TestReadOnlyLacks_Known(t *testing.T) {
	defer func(g string, p func() bool) { goos, pwshInstalled = g, p }(goos, pwshInstalled)
	pwshInstalled = func() bool { return true }
	var all []string
	for _, g := range []string{"darwin", "linux"} {
		goos = g
		all = append(all, Capabilities()...)
	}
	goos = "windows"
	all = append(all, Capabilities()...)
	all = append(all, CapabilityScriptPwsh)
	for _, c := range ReadOnlyLacks {
		if !slices.Contains(all, c) {
			t.Errorf("ReadOnlyLacks has %q, which no build advertises", c)
		}
	}
}

func TestWithoutReadOnlyLacks(t *testing.T) {
	got := withoutReadOnlyLacks([]string{"script_inline_body_v1", "yara_scan_v1", CapabilityMDMEnroll, "packages_v1"})
	if !slices.Equal(got, []string{"packages_v1"}) {
		t.Errorf("withoutReadOnlyLacks = %v", got)
	}
}
