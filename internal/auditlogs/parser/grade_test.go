package parser

import (
	"testing"

	"sentinelgo/internal/auditlogs/collector"
)

func TestSendable(t *testing.T) {
	for sev, want := range map[string]bool{
		SeverityCritical: true, SeverityHigh: true,
		SeverityMedium: false, SeverityLow: false, SeverityInfo: false, "": false, "HIGH": false,
	} {
		if got := Sendable(sev); got != want {
			t.Errorf("Sendable(%q) = %v, want %v", sev, got, want)
		}
	}
}

// TestGrade_Windows covers every Windows rule in #484. Severity is the
// syslog-style level the Windows collector emits: "6" Information (and the
// Security log's level 0), "4" Warning, "7" Verbose.
func TestGrade_Windows(t *testing.T) {
	tests := []struct {
		source, id, level, want string
	}{
		{collector.SourceWindowsSecurity, "1102", "6", SeverityCritical},
		{collector.SourceWindowsSecurity, "4719", "6", SeverityCritical},
		{collector.SourceWindowsSecurity, "4625", "6", SeverityHigh},
		{collector.SourceWindowsSecurity, "4720", "6", SeverityHigh},
		{collector.SourceWindowsSecurity, "4722", "6", SeverityHigh},
		{collector.SourceWindowsSecurity, "4723", "6", SeverityHigh},
		{collector.SourceWindowsSecurity, "4724", "6", SeverityHigh},
		{collector.SourceWindowsSecurity, "4725", "6", SeverityHigh},
		{collector.SourceWindowsSecurity, "4726", "6", SeverityHigh},
		{collector.SourceWindowsSecurity, "4738", "6", SeverityHigh},
		{collector.SourceWindowsSecurity, "4731", "6", SeverityHigh},
		{collector.SourceWindowsSecurity, "4732", "6", SeverityHigh},
		{collector.SourceWindowsSecurity, "4733", "6", SeverityHigh},
		{collector.SourceWindowsSecurity, "4734", "6", SeverityHigh},
		{collector.SourceWindowsSecurity, "4739", "6", SeverityHigh},
		{collector.SourceWindowsSecurity, "4624", "6", SeverityInfo}, // routine logon
		{collector.SourceWindowsSecurity, "4688", "6", SeverityInfo}, // process creation
		{collector.SourceWindowsSystem, "104", "6", SeverityCritical},
		{collector.SourceWindowsSystem, "7045", "6", SeverityHigh},
		{collector.SourceWindowsSystem, "7036", "6", SeverityInfo},
		{collector.SourceWindowsSystem, "41", "2", SeverityCritical}, // OS level kept
		{collector.SourceWindowsDefender, "1006", "4", SeverityCritical},
		{collector.SourceWindowsDefender, "1015", "4", SeverityCritical},
		{collector.SourceWindowsDefender, "1116", "4", SeverityCritical},
		{collector.SourceWindowsDefender, "1008", "3", SeverityCritical},
		{collector.SourceWindowsDefender, "1118", "4", SeverityCritical},
		{collector.SourceWindowsDefender, "1119", "3", SeverityCritical},
		{collector.SourceWindowsDefender, "5001", "4", SeverityCritical},
		{collector.SourceWindowsDefender, "5010", "4", SeverityCritical},
		{collector.SourceWindowsDefender, "5012", "4", SeverityCritical},
		{collector.SourceWindowsDefender, "1007", "6", SeverityHigh},
		{collector.SourceWindowsDefender, "1117", "6", SeverityHigh},
		{collector.SourceWindowsDefender, "5004", "6", SeverityHigh},
		{collector.SourceWindowsDefender, "5007", "6", SeverityHigh},
		{collector.SourceWindowsDefender, "5013", "4", SeverityHigh},
		{collector.SourceWindowsDefender, "1001", "6", SeverityInfo}, // scan finished
		{collector.SourceWindowsPowerShell, "4104", "4", SeverityHigh},
		{collector.SourceWindowsPowerShell, "4104", "7", SeverityInfo},
		{collector.SourceWindowsTaskScheduler, "106", "6", SeverityHigh},
		{collector.SourceWindowsTaskScheduler, "200", "6", SeverityInfo},
		{collector.SourceWindowsFirewall, "2003", "6", SeverityHigh},
		{collector.SourceWindowsFirewall, "2004", "6", SeverityInfo},
		{collector.SourceWindowsRemoteDesktop, "1149", "6", SeverityHigh},
		{collector.SourceWindowsRemoteDesktop, "261", "6", SeverityInfo},
		{"windows_application", "1000", "3", SeverityHigh}, // application error: OS level
		{"windows_application", "4625", "6", SeverityInfo}, // IDs graded per source only
	}
	for _, tt := range tests {
		raw := collector.RawLogEntry{Source: tt.source, EventID: tt.id, Severity: tt.level}
		if got := grade(&raw); got != tt.want {
			t.Errorf("grade(%s %s level %s) = %q, want %q", tt.source, tt.id, tt.level, got, tt.want)
		}
	}
}

// TestGrade_SignInAndAccounts covers the Linux and macOS message rules in
// #484, from the journal (identifier), the unified log (process) and syslog
// text files (the program in the line).
func TestGrade_SignInAndAccounts(t *testing.T) {
	tests := []struct {
		name, source string
		meta         map[string]string
		msg, level   string
		want         string
	}{
		{"journal ssh failure", "journal", map[string]string{"identifier": "sshd"}, "Failed password for root from 10.0.0.1 port 22 ssh2", "6", SeverityHigh},
		{"journal ssh invalid user", "journal", map[string]string{"identifier": "sshd-session"}, "Invalid user admin from 10.0.0.1", "6", SeverityHigh},
		{"journal ssh sign-in", "journal", map[string]string{"identifier": "sshd"}, "Accepted publickey for alice from 10.0.0.1", "6", SeverityHigh},
		{"journal ssh routine", "journal", map[string]string{"identifier": "sshd"}, "Received disconnect from 10.0.0.1", "6", SeverityInfo},
		{"journal sudo wrong password", "journal", map[string]string{"identifier": "sudo"}, "alice : 3 incorrect password attempts ; TTY=pts/0", "5", SeverityHigh},
		{"journal sudo not allowed", "journal", map[string]string{"identifier": "sudo"}, "bob : user NOT in sudoers ; TTY=pts/1", "5", SeverityHigh},
		{"journal sudo command", "journal", map[string]string{"identifier": "sudo"}, "alice : TTY=pts/0 ; COMMAND=/usr/bin/apt update", "5", SeverityLow},
		{"journal useradd", "journal", map[string]string{"identifier": "useradd"}, "new user: name=eve, UID=1002", "6", SeverityHigh},
		{"journal passwd", "journal", map[string]string{"identifier": "passwd"}, "pam_unix(passwd:chauthtok): password changed for alice", "5", SeverityHigh},
		{"journal other", "journal", map[string]string{"identifier": "systemd"}, "Started Daily apt download activities.", "6", SeverityInfo},
		{"auth.log ssh failure", "auth.log", nil, "Nov 13 10:00:00 host sshd[1234]: Failed password for root from 10.0.0.1", "3", SeverityHigh},
		{"auth.log su failure", "auth.log", nil, "Nov 13 10:00:00 host su[99]: FAILED su for root by alice", "3", SeverityHigh},
		{"auth.log groupadd", "auth.log", nil, "Nov 13 10:00:00 host groupadd[77]: group added to /etc/group: name=dev", "6", SeverityHigh},
		{"auth.log cron", "auth.log", nil, "Nov 13 10:00:00 host CRON[5]: pam_unix(cron:session): session opened for user root", "6", SeverityInfo},
		{"oslog sudo failure", "oslog", map[string]string{"process": "sudo"}, "alice : 1 incorrect password attempt ; TTY=ttys000", "5", SeverityHigh},
		{"oslog fault", "oslog", map[string]string{"process": "kernel"}, "panic", "2", SeverityCritical},
		{"oslog default", "oslog", map[string]string{"process": "WindowServer"}, "display changed", "5", SeverityLow},
	}
	for _, tt := range tests {
		meta := tt.meta
		if meta == nil {
			meta = map[string]string{}
		}
		raw := collector.RawLogEntry{Source: tt.source, RawMessage: tt.msg, Severity: tt.level, Metadata: meta}
		if got := grade(&raw); got != tt.want {
			t.Errorf("%s: grade = %q, want %q", tt.name, got, tt.want)
		}
	}
}

// TestGrade_NeverLowers: a rule only raises a severity.
func TestGrade_NeverLowers(t *testing.T) {
	raw := collector.RawLogEntry{Source: collector.SourceWindowsDefender, EventID: "1117", Severity: "2"}
	if got := grade(&raw); got != SeverityCritical {
		t.Errorf("grade = %q, want critical (OS level kept over the rule's high)", got)
	}
}
