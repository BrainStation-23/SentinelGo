package security

// AutoRun/AutoPlay and application control (#178): the optional
// security_info.autorun and security_info.application_control keys. The
// parsers have no OS suffix so they compile and are tested on every platform;
// appcontrol_<os>.go reads the raw values.

import (
	"encoding/xml"
	"strings"

	"sentinelgo/internal/osinfo/shared"
)

// noDriveTypeAllDrives is the NoDriveTypeAutoRun mask that turns AutoPlay off
// for every drive type ("Turn off AutoPlay: All drives").
const noDriveTypeAllDrives = 0xFF

// winAutoplayUser is one signed-in user's AutoPlay settings, read from their
// hive under HKEY_USERS: the user's "Turn off AutoPlay" policy
// (NoDriveTypeAutoRun) and the Settings switch (AutoplayHandlers
// DisableAutoplay). -1 means the value isn't set.
type winAutoplayUser struct {
	PolicyNoDriveType int
	DisableAutoplay   int
}

// windowsAutoRun combines the machine AutoRun/AutoPlay policies with the
// signed-in users' settings. machineNoDriveType and machineNoAutorun are
// NoDriveTypeAutoRun and NoAutorun under HKLM\...\Policies\Explorer (-1 when
// unset, which is the Windows default: AutoRun and AutoPlay on).
//
// AutoRun is disabled only when the machine policy turns it off for all
// drives and sets "Do not execute any autorun commands" (NoAutorun = 1).
// AutoPlay is disabled by the machine policy, or else when every signed-in
// user has it off by their own policy or in Settings. With no machine policy
// and nobody signed in there is no setting to read, so it is left out.
func windowsAutoRun(machineNoDriveType, machineNoAutorun int, users []winAutoplayUser) *shared.AutoRunInfo {
	machineAll := allDrives(machineNoDriveType)
	info := &shared.AutoRunInfo{
		AutoRunDisabled: shared.Bool(machineAll && machineNoAutorun == 1),
	}
	switch {
	case machineAll:
		info.AutoPlayDisabled = shared.Bool(true)
	case len(users) > 0:
		off := true
		for _, u := range users {
			off = off && (allDrives(u.PolicyNoDriveType) || u.DisableAutoplay == 1)
		}
		info.AutoPlayDisabled = shared.Bool(off)
	}
	return info
}

func allDrives(noDriveType int) bool {
	return noDriveType >= 0 && noDriveType&noDriveTypeAllDrives == noDriveTypeAllDrives
}

// appControlRank orders modes from weakest to strongest.
var appControlRank = map[string]int{
	shared.AppControlOff:      1,
	shared.AppControlAudit:    2,
	shared.AppControlEnforced: 3,
}

// strongestAppControl returns the candidate with the strongest mode; on a tie
// the earlier one wins. nil candidates (products that couldn't be read) are
// skipped, and nil is returned when none could be read.
func strongestAppControl(candidates ...*shared.ApplicationControlInfo) *shared.ApplicationControlInfo {
	var best *shared.ApplicationControlInfo
	for _, c := range candidates {
		if c == nil || appControlRank[c.Mode] == 0 {
			continue
		}
		if best == nil || appControlRank[c.Mode] > appControlRank[best.Mode] {
			best = c
		}
	}
	return best
}

// wdacControl maps Win32_DeviceGuard.UsermodeCodeIntegrityPolicyEnforcementStatus
// (0 off, 1 audit, 2 enforced) to application_control; nil when it wasn't
// read or is outside that range. The user-mode status is the one that
// decides which applications may run. The kernel-mode
// CodeIntegrityPolicyEnforcementStatus is 2 on every Windows 11 machine,
// because the built-in vulnerable driver blocklist is itself a WDAC policy,
// so it says nothing about application control.
func wdacControl(status *int) *shared.ApplicationControlInfo {
	if status == nil {
		return nil
	}
	modes := map[int]string{0: shared.AppControlOff, 1: shared.AppControlAudit, 2: shared.AppControlEnforced}
	mode, ok := modes[*status]
	if !ok {
		return nil
	}
	return &shared.ApplicationControlInfo{Product: shared.AppControlWDAC, Mode: mode}
}

// appLockerPolicyXML is the part of `Get-AppLockerPolicy -Effective -Xml`
// this reads: each rule collection's enforcement mode and how many rules it
// holds.
type appLockerPolicyXML struct {
	Collections []struct {
		EnforcementMode string `xml:"EnforcementMode,attr"`
		Children        []struct {
			XMLName xml.Name
		} `xml:",any"`
	} `xml:"RuleCollection"`
}

// parseAppLockerPolicy returns the AppLocker mode from the effective policy
// XML: enforced when a rule collection with rules is enforced (EnforcementMode
// Enabled, or NotConfigured, which enforces once the collection has rules),
// audit when the only collections with rules are AuditOnly, and off when no
// collection has rules. ok is false when the output isn't a policy.
func parseAppLockerPolicy(policyXML string) (mode string, ok bool) {
	policyXML = strings.TrimSpace(strings.TrimPrefix(policyXML, "ï»¿"))
	if policyXML == "" {
		return "", false
	}
	var p appLockerPolicyXML
	if err := xml.Unmarshal([]byte(policyXML), &p); err != nil {
		return "", false
	}
	mode = shared.AppControlOff
	for _, c := range p.Collections {
		if !hasAppLockerRules(c.Children) {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(c.EnforcementMode)) {
		case "auditonly":
			mode = shared.AppControlAudit
		case "", "enabled", "notconfigured":
			return shared.AppControlEnforced, true
		}
	}
	return mode, true
}

// hasAppLockerRules reports whether a rule collection holds rules
// (FilePathRule, FilePublisherRule, FileHashRule), not just settings such as
// RuleCollectionExtensions.
func hasAppLockerRules(children []struct{ XMLName xml.Name }) bool {
	for _, c := range children {
		if strings.HasSuffix(c.XMLName.Local, "Rule") {
			return true
		}
	}
	return false
}

// appLockerControl reports AppLocker from its policy mode. Rules are only
// applied while the Application Identity service (AppIDSvc) runs, so a
// policy with rules counts as off when it doesn't. nil when the policy
// couldn't be read.
func appLockerControl(mode string, ok, appIDRunning bool) *shared.ApplicationControlInfo {
	if !ok {
		return nil
	}
	if !appIDRunning {
		mode = shared.AppControlOff
	}
	return &shared.ApplicationControlInfo{Product: shared.AppControlAppLocker, Mode: mode}
}

// parseSpctlStatus reads `spctl --status` ("assessments enabled" or
// "assessments disabled", on a line of its own); ok is false when neither
// is found.
func parseSpctlStatus(output string) (enabled, ok bool) {
	for _, line := range strings.Split(output, "\n") {
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "assessments enabled":
			return true, true
		case "assessments disabled":
			return false, true
		}
	}
	return false, false
}

// gatekeeperControl reports Gatekeeper from `spctl --status`; nil when the
// output wasn't recognised.
func gatekeeperControl(spctlOutput string) *shared.ApplicationControlInfo {
	enabled, ok := parseSpctlStatus(spctlOutput)
	if !ok {
		return nil
	}
	mode := shared.AppControlOff
	if enabled {
		mode = shared.AppControlEnforced
	}
	return &shared.ApplicationControlInfo{Product: shared.AppControlGatekeeper, Mode: mode}
}

// fapolicydControl reports fapolicyd: nil when it isn't installed (or
// systemd couldn't be queried), off when installed but not running, and
// otherwise enforced or audit from fapolicyd.conf's permissive setting
// (0, the default, enforces; 1 only logs). A running daemon whose config
// couldn't be read is left out.
func fapolicydControl(active, unitFiles map[string]string, conf string, confOK bool) *shared.ApplicationControlInfo {
	const unit = "fapolicyd.service"
	_, installed := unitFiles[unit]
	_, running := active[unit]
	if !installed && !running {
		return nil
	}
	info := &shared.ApplicationControlInfo{Product: shared.AppControlFapolicyd, Mode: shared.AppControlOff}
	if !running {
		return info
	}
	if !confOK {
		return nil
	}
	info.Mode = shared.AppControlEnforced
	if strings.TrimSpace(parseKeyValueConf(conf)["permissive"]) == "1" {
		info.Mode = shared.AppControlAudit
	}
	return info
}
