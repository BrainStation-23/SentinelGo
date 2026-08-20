package sessions

import "testing"

func sessionEqual(a, b Session) bool {
	return a.Username == b.Username && a.SessionName == b.SessionName &&
		a.SessionType == b.SessionType && a.Remote == b.Remote && a.State == b.State
}

// ── quser (Windows) ──────────────────────────────────────────────────────────

func TestParseQuser_ConsoleAndRDP(t *testing.T) {
	const sample = ` USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>administrator         console             1  Active       .     8/20/2026 9:15 AM
 jdoe                  rdp-tcp#3           2  Active      5      8/19/2026 2:30 PM
`
	got := parseQuser(sample)
	want := []Session{
		{Username: "administrator", SessionName: "console", SessionType: "console", Remote: false, State: "Active"},
		{Username: "jdoe", SessionName: "rdp-tcp#3", SessionType: "rdp", Remote: true, State: "Active"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d sessions, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if !sessionEqual(got[i], want[i]) {
			t.Errorf("session %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseQuser_DisconnectedBlankSessionName(t *testing.T) {
	// SESSIONNAME is blank for a disconnected session — the exact case that
	// breaks naive whitespace splitting, since the ID column shifts left.
	const sample = ` USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
 jdoe                                      2  Disc        5      8/19/2026 2:30 PM
`
	got := parseQuser(sample)
	if len(got) != 1 {
		t.Fatalf("got %d sessions, want 1: %+v", len(got), got)
	}
	s := got[0]
	if s.Username != "jdoe" {
		t.Errorf("username = %q, want jdoe", s.Username)
	}
	if s.SessionName != "" {
		t.Errorf("session name = %q, want empty", s.SessionName)
	}
	if s.SessionType != "disconnected" {
		t.Errorf("session type = %q, want disconnected", s.SessionType)
	}
	if s.Remote {
		t.Error("a disconnected session's remote-ness is unknown and must not be guessed true")
	}
	if s.State != "Disc" {
		t.Errorf("state = %q, want Disc", s.State)
	}
}

func TestParseQuser_NoSessions(t *testing.T) {
	const sample = ` USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
`
	if got := parseQuser(sample); len(got) != 0 {
		t.Errorf("got %d sessions, want 0: %+v", len(got), got)
	}
}

func TestParseQuser_UnrecognisedFormat(t *testing.T) {
	if got := parseQuser("No User exists for *"); len(got) != 0 {
		t.Errorf("got %d sessions from unrecognised output, want 0: %+v", len(got), got)
	}
	if got := parseQuser(""); len(got) != 0 {
		t.Errorf("got %d sessions from empty output, want 0: %+v", len(got), got)
	}
}

// ── loginctl (Linux) ─────────────────────────────────────────────────────────

func TestParseLoginctlList(t *testing.T) {
	const sample = `[{"session":"1","uid":1000,"user":"jdoe","seat":"seat0"},{"session":"c3","uid":1001,"user":"asmith","seat":""}]`
	got, err := parseLoginctlList(sample)
	if err != nil {
		t.Fatalf("parseLoginctlList: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d sessions, want 2: %+v", len(got), got)
	}
	if got[0].Session != "1" || got[0].User != "jdoe" || got[0].Seat != "seat0" {
		t.Errorf("session 0 = %+v", got[0])
	}
	if got[1].Seat != "" {
		t.Errorf("session 1 seat = %q, want empty", got[1].Seat)
	}
}

func TestParseLoginctlList_Malformed(t *testing.T) {
	if _, err := parseLoginctlList("not json"); err == nil {
		t.Error("expected an error for malformed JSON, got nil")
	}
}

func TestParseKeyEqualsValue(t *testing.T) {
	const sample = "Remote=no\nState=active\n"
	got := parseKeyEqualsValue(sample)
	if got["Remote"] != "no" || got["State"] != "active" {
		t.Errorf("got %+v", got)
	}
}

func TestClassifyLoginctlSession(t *testing.T) {
	tests := []struct {
		name       string
		seat       string
		remoteProp string
		wantType   string
		wantRemote bool
	}{
		{"ssh session", "", "yes", "ssh", true},
		{"physical console", "seat0", "no", "console", false},
		{"seated but also remote (Remote wins)", "seat0", "yes", "ssh", true},
		{"no seat, not remote (e.g. cron/screen)", "", "no", "other", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotType, gotRemote := classifyLoginctlSession(tc.seat, tc.remoteProp)
			if gotType != tc.wantType || gotRemote != tc.wantRemote {
				t.Errorf("classifyLoginctlSession(%q, %q) = (%q, %v), want (%q, %v)",
					tc.seat, tc.remoteProp, gotType, gotRemote, tc.wantType, tc.wantRemote)
			}
		})
	}
}

// ── who (macOS) ──────────────────────────────────────────────────────────────

func TestParseWho(t *testing.T) {
	const sample = `jdoe     console      Aug 20 09:15
jdoe     ttys000      Aug 20 10:02 (192.168.1.50)
asmith   ttys001      Aug 20 11:00
`
	got := parseWho(sample)
	want := []Session{
		{Username: "jdoe", SessionName: "console", SessionType: "console", Remote: false},
		{Username: "jdoe", SessionName: "ttys000", SessionType: "ssh", Remote: true},
		{Username: "asmith", SessionName: "ttys001", SessionType: "terminal", Remote: false},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d sessions, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if !sessionEqual(got[i], want[i]) {
			t.Errorf("session %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestParseWho_Empty(t *testing.T) {
	if got := parseWho(""); len(got) != 0 {
		t.Errorf("got %d sessions, want 0: %+v", len(got), got)
	}
}
