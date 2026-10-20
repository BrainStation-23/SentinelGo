package security

// Fuzz target for the compliance telemetry parsers (#172). They read config
// files and tool output on the host (PAM, login.defs, gsettings, pmset,
// pwpolicy plists, secedit, auditpol, PowerShell JSON, AppLocker XML, spctl,
// fapolicyd.conf), which a local user or package can shape, so the parsing
// must never panic on unexpected input.
//
// The seed corpus runs as an ordinary unit test under `go test ./...`.
// To fuzz: go test -run='^$' -fuzz='^FuzzComplianceParsers$' -fuzztime=1m ./internal/osinfo/security/

import (
	"strings"
	"testing"
	"time"
)

func FuzzComplianceParsers(f *testing.F) {
	for _, s := range []string{
		seceditSample, auditpolSample, debianCommonPassword, rhelSystemAuth, pwpolicySample,
		"", "\n", "=", "[", "{", "null", "[]", "[null]", `{"GuestEnabled":1}`,
		"password requisite pam_pwquality.so minlen=", "auth [default=die] pam_faillock.so authfail deny=",
		"uint32 ", "uint32 99999999999999999999", "displaysleep 99999999999999999999",
		"[daemon]\nAutomaticLoginEnable=true", "[Seat:*]\nautologin-user=", "server min protocol = NT1",
		"<plist><dict><key>minimumLength</key><integer>99999999999999999999</integer></dict></plist>",
		"<plist><dict><key>minimumLength</key><real>1e300</real></dict></plist>",
		`<AppLockerPolicy><RuleCollection EnforcementMode="Enabled"><FilePathRule/></RuleCollection></AppLockerPolicy>`,
		"<AppLockerPolicy><RuleCollection>", "assessments enabled", "permissive = 1",
		"-a always,exit -k", "Leap status : Normal\nSystem time : 1e400 seconds", "*1.2.3.4 .GPS. 1 u 1 64 1 0.1 -1e309 0.1",
		strings.Repeat("password required pam_unix.so ", 500),
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		// Linux
		_ = parsePAM(s)
		_ = linuxPasswordPolicy(linuxPasswordSources{LoginDefs: s, PwQuality: s, Faillock: s, PwHistory: s, PAM: s, PAMRead: true})
		_ = parseLoginDefs(s)
		_ = parseLoginctlSessions(s)
		_ = isActiveGraphicalSession(s)
		_ = gnomeScreenLock("true", s, s, s)
		_ = gdmAutoLogin(s)
		_, _ = lightdmLogin(s)
		_ = sddmAutoLogin(s)
		_ = gettyAutoLogin(s)
		_ = parseUnitList(s)
		_ = smbMinProtocolAllowsSMB1(s)
		_, _ = lastDpkgUpgrade(s, time.UTC)
		_, _ = lastDnfUpgrade(s)
		_, _ = lastPacmanUpgrade(s, time.UTC)
		_, _ = needrestartKernelPending(s)
		_ = aptUnattendedEnabled(s)
		_ = dnfAutomaticApplies(s)
		_, _ = parseAuditRules(s)
		_, _ = timedatectlNTP(s)
		_, _ = parseChronyTracking(s)
		_, _ = parseTimesyncStatus(s)
		_ = parseSystemdTimespan(s)
		_, _ = parseNtpqPeers(s)

		// macOS
		_ = macPasswordPolicy(s)
		_, _, _ = parseSysadminctlScreenLock(s)
		_, _ = parsePmsetDisplaySleep(s)
		_, _ = parseAuditControl(s)
		_ = colonValue(s)
		_, _ = parseTimeMachineLatest(s, time.UTC)
		_ = tmHasDestination(s)

		// Windows
		_ = parseSeceditPasswordPolicy(s)
		_, _, _ = parseAuditpolBackup(s)
		_, _ = parseWinComplianceProbe(s)
		_, _, _ = parseWindowsMissingUpdates(s)

		// Application control (#178)
		_, _ = parseAppLockerPolicy(s)
		_ = gatekeeperControl(s)
		_ = fapolicydControl(map[string]string{"fapolicyd.service": ""}, map[string]string{}, s, true)
	})
}
