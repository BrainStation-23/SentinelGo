package persistence

import "testing"

func TestParseWindowsTasks_Array(t *testing.T) {
	const sample = `[{"Name":"Backup","Path":"\\","Command":"C:\\backup.exe","Enabled":true}]`
	rows, err := parseWindowsTasks(sample)
	if err != nil {
		t.Fatalf("parseWindowsTasks: %v", err)
	}
	if len(rows) != 1 || rows[0].Name != "Backup" {
		t.Fatalf("got %+v", rows)
	}
}

func TestParseWindowsTasks_Empty(t *testing.T) {
	rows, err := parseWindowsTasks("")
	if err != nil || rows != nil {
		t.Errorf("got (%v, %v), want (nil, nil)", rows, err)
	}
}

func TestParseSystemctlShow(t *testing.T) {
	const sample = `Id=sshd.service
ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D $OPTIONS ; ignore_errors=no ; start_time=... }
FragmentPath=/usr/lib/systemd/system/sshd.service
UnitFileState=enabled
Id=bluetooth.service
ExecStart={ path=/usr/libexec/bluetooth/bluetoothd ; argv[]=/usr/libexec/bluetooth/bluetoothd ; }
FragmentPath=/usr/lib/systemd/system/bluetooth.service
UnitFileState=disabled
`
	got := parseSystemctlShow(sample)
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(got), got)
	}
	if got[0].Name != "sshd.service" || got[0].Command != "/usr/sbin/sshd -D $OPTIONS" {
		t.Errorf("entry 0 = %+v", got[0])
	}
	if got[0].Enabled == nil || !*got[0].Enabled {
		t.Errorf("entry 0 enabled = %v, want true", got[0].Enabled)
	}
	if got[1].Name != "bluetooth.service" {
		t.Errorf("entry 1 = %+v", got[1])
	}
	if got[1].Enabled == nil || *got[1].Enabled {
		t.Errorf("entry 1 enabled = %v, want false", got[1].Enabled)
	}
}

func TestParseSystemctlShow_Empty(t *testing.T) {
	if got := parseSystemctlShow(""); got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

func TestParseCrontab_SystemFormat(t *testing.T) {
	const sample = `# comment
MAILTO=root
PATH=/usr/bin:/bin
17 *	* * *	root	cd / && run-parts --report /etc/cron.daily
25 6	* * *	root	test -x /usr/sbin/anacron
`
	got := parseCrontab(sample, true, "/etc/crontab")
	if len(got) != 2 {
		t.Fatalf("got %d entries, want 2 (MAILTO/PATH lines and comments must be skipped): %+v", len(got), got)
	}
	if got[0].Command != "cd / && run-parts --report /etc/cron.daily" {
		t.Errorf("entry 0 command = %q", got[0].Command)
	}
	if got[0].Location != "/etc/crontab" {
		t.Errorf("entry 0 location = %q", got[0].Location)
	}
}

func TestParseCrontab_PerUserFormat(t *testing.T) {
	const sample = `# per-user crontab, no user field
0 2 * * * /home/jdoe/backup.sh
`
	got := parseCrontab(sample, false, "/var/spool/cron/jdoe")
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1: %+v", len(got), got)
	}
	if got[0].Command != "/home/jdoe/backup.sh" {
		t.Errorf("command = %q", got[0].Command)
	}
}

func TestParseCrontab_WrongFormatMisparsesGracefully(t *testing.T) {
	// A per-user-format line parsed with systemCrontab=true (expecting an
	// extra user field) has too few fields for a 1-word command and is
	// dropped rather than silently eating part of the command.
	const sample = `0 2 * * * /home/jdoe/backup.sh
`
	got := parseCrontab(sample, true, "/etc/cron.d/foo")
	if len(got) != 0 {
		t.Errorf("got %+v, want no entries (5 time fields + 1 word is below the 7-field system-format minimum)", got)
	}
}

func TestParseLaunchdPlist(t *testing.T) {
	const sample = `{"Label":"com.example.agent","ProgramArguments":["/usr/local/bin/agent","--flag"]}`
	entry, ok := parseLaunchdPlist(sample, "/Library/LaunchAgents/com.example.agent.plist")
	if !ok {
		t.Fatal("parseLaunchdPlist returned ok=false")
	}
	if entry.Name != "com.example.agent" || entry.Command != "/usr/local/bin/agent --flag" {
		t.Errorf("entry = %+v", entry)
	}
	if entry.Enabled == nil || !*entry.Enabled {
		t.Errorf("Enabled = %v, want true (no Disabled key)", entry.Enabled)
	}
}

func TestParseLaunchdPlist_Disabled(t *testing.T) {
	const sample = `{"Label":"com.example.agent","Program":"/usr/local/bin/agent","Disabled":true}`
	entry, ok := parseLaunchdPlist(sample, "/path")
	if !ok {
		t.Fatal("parseLaunchdPlist returned ok=false")
	}
	if entry.Enabled == nil || *entry.Enabled {
		t.Errorf("Enabled = %v, want false", entry.Enabled)
	}
}

func TestParseLaunchdPlist_Malformed(t *testing.T) {
	if _, ok := parseLaunchdPlist("not json", "/path"); ok {
		t.Error("expected ok=false for malformed JSON")
	}
	if _, ok := parseLaunchdPlist(`{"Label":""}`, "/path"); ok {
		t.Error("expected ok=false for an empty Label")
	}
}

func TestIsAppleOwnedLaunchdLabel(t *testing.T) {
	if !isAppleOwnedLaunchdLabel("com.apple.something") {
		t.Error("com.apple.* should be filtered")
	}
	if isAppleOwnedLaunchdLabel("com.example.agent") {
		t.Error("a third-party label should not be filtered")
	}
}
