package parser

import (
	"regexp"
	"strings"

	"sentinelgo/internal/auditlogs/collector"
)

// Severities, most severe first: the set the backend accepts.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Sendable reports whether a log of this severity is sent to the backend:
// only high and critical ones are (#484). The backend is a compliance
// platform, not a log store.
func Sendable(severity string) bool {
	return severity == SeverityCritical || severity == SeverityHigh
}

var severityRank = map[string]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// grade is the entry's severity: the OS level (normalizeSeverity), raised for
// the security events below, which the OS logs at a lower level than they
// deserve (#484). Windows logs failed logons and account changes as
// Information and Defender detections as Warning; a filter on the OS level
// alone would drop them. A rule never lowers a severity.
func grade(raw *collector.RawLogEntry) string {
	sev := normalizeSeverity(raw.Severity)
	if g := eventGrade(raw); severityRank[g] > severityRank[sev] {
		return g
	}
	return sev
}

// windowsGrades are the event IDs graded per Windows source.
var windowsGrades = map[string]map[string]string{
	collector.SourceWindowsSecurity: {
		"1102": SeverityCritical, // the Security log was cleared
		"4719": SeverityCritical, // audit policy changed
		"4625": SeverityHigh,     // failed logon
		"4720": SeverityHigh,     // account created
		"4722": SeverityHigh,     // account enabled
		"4723": SeverityHigh,     // password change attempted
		"4724": SeverityHigh,     // password reset attempted
		"4725": SeverityHigh,     // account disabled
		"4726": SeverityHigh,     // account deleted
		"4738": SeverityHigh,     // account changed
		"4731": SeverityHigh,     // local group created
		"4732": SeverityHigh,     // member added to a local group (e.g. Administrators)
		"4733": SeverityHigh,     // member removed from a local group
		"4734": SeverityHigh,     // local group deleted
		"4739": SeverityHigh,     // domain policy changed
	},
	collector.SourceWindowsSystem: {
		"104":  SeverityCritical, // an event log was cleared
		"7045": SeverityHigh,     // a service was installed
	},
	collector.SourceWindowsDefender: {
		"1006": SeverityCritical, // malware detected
		"1015": SeverityCritical, // suspicious behaviour detected
		"1116": SeverityCritical, // malware detected
		"1008": SeverityCritical, // action on malware failed
		"1118": SeverityCritical, // action on malware failed
		"1119": SeverityCritical, // critical error acting on malware
		"5001": SeverityCritical, // real-time protection disabled
		"5010": SeverityCritical, // scanning for spyware disabled
		"5012": SeverityCritical, // scanning for viruses disabled
		"1007": SeverityHigh,     // action taken on malware
		"1117": SeverityHigh,     // action taken on malware
		"5004": SeverityHigh,     // real-time protection configuration changed
		"5007": SeverityHigh,     // configuration changed
		"5013": SeverityHigh,     // tamper protection blocked a change
	},
	collector.SourceWindowsTaskScheduler: {
		"106": SeverityHigh, // a scheduled task was registered
	},
	collector.SourceWindowsFirewall: {
		"2003": SeverityHigh, // a firewall profile setting changed
	},
	collector.SourceWindowsRemoteDesktop: {
		"1149": SeverityHigh, // remote desktop sign-in
	},
}

// eventGrade is the severity a rule assigns to the entry, or "" when no rule
// matches.
func eventGrade(raw *collector.RawLogEntry) string {
	if ids, ok := windowsGrades[raw.Source]; ok {
		return ids[raw.EventID]
	}
	if raw.Source == collector.SourceWindowsPowerShell {
		// 4104 is logged at Warning ("4") when Windows flags the script
		// block as suspicious; ordinary script blocks are Verbose.
		if raw.EventID == "4104" && strings.TrimSpace(raw.Severity) == "4" {
			return SeverityHigh
		}
		return ""
	}
	if strings.HasPrefix(raw.Source, "windows_") {
		return ""
	}
	return messageGrade(raw)
}

// authToolRe finds the program in a syslog-style line ("host sshd[12]: ...").
var authToolRe = regexp.MustCompile(`(?:^|\s)(sshd-session|sshd|sudo|su|useradd|userdel|usermod|groupadd|groupdel|gpasswd|chpasswd|passwd)(?:\[\d+\])?:`)

// accountTools change accounts or groups; any message from them is an account
// change.
var accountTools = map[string]bool{
	"useradd": true, "userdel": true, "usermod": true,
	"groupadd": true, "groupdel": true, "gpasswd": true, "chpasswd": true,
}

// signInPhrases mark sign-ins and failed sign-ins in sshd (sshd-session from
// OpenSSH 9.8), sudo, su and PAM messages.
var signInPhrases = []string{
	"Failed password",
	"Invalid user",
	"authentication failure",
	"Accepted password",
	"Accepted publickey",
	"Accepted keyboard-interactive",
	"incorrect password attempt",
	"NOT in sudoers",
	"FAILED su",
}

// messageGrade grades Linux and macOS sign-in and account events by message
// (journal, auth.log, syslog, unified log): they are logged at info or notice
// level. Everything else keeps its OS level.
func messageGrade(raw *collector.RawLogEntry) string {
	tool := raw.Metadata["identifier"]
	if tool == "" {
		tool = raw.Metadata["process"]
	}
	if tool == "" {
		if m := authToolRe.FindStringSubmatch(raw.RawMessage); m != nil {
			tool = m[1]
		}
	}
	switch {
	case accountTools[tool]:
		return SeverityHigh
	case tool == "passwd":
		if strings.Contains(raw.RawMessage, "password changed") {
			return SeverityHigh
		}
	case tool == "sshd" || tool == "sshd-session" || tool == "sudo" || tool == "su":
		for _, p := range signInPhrases {
			if strings.Contains(raw.RawMessage, p) {
				return SeverityHigh
			}
		}
	}
	return ""
}
