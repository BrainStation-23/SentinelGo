//go:build windows

package software

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// timeToFileTime converts a UTC time to a Windows FILETIME (100-ns intervals
// since 1601-01-01), the inverse of fileTimeToTime.
func timeToFileTime(t time.Time) uint64 {
	return uint64(t.UnixNano()/100) + fileTimeToUnixOffset
}

// userAssistBlob builds a modern (72-byte) UserAssist Count value whose last-run
// FILETIME is set to ft.
func userAssistBlob(ft uint64) []byte {
	data := make([]byte, 72)
	binary.LittleEndian.PutUint32(data[4:8], 9) // run count (ignored by parser)
	binary.LittleEndian.PutUint64(data[userAssistLastRunOffset:userAssistLastRunOffset+8], ft)
	return data
}

func TestRot13RoundTrip(t *testing.T) {
	const s = `{6D809377-6AF0-444B-8957-A3773F02200E}\Git\bin\git.exe`
	if got := rot13(rot13(s)); got != s {
		t.Errorf("rot13 round-trip = %q, want %q", got, s)
	}
}

func TestNormalizeUserAssistPath(t *testing.T) {
	roots := map[string]string{
		"{6d809377-6af0-444b-8957-a3773f02200e}": `C:\Program Files`,
	}
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"resolved guid prefix", `{6D809377-6AF0-444B-8957-A3773F02200E}\Git\bin\git.exe`, `C:\Program Files\Git\bin\git.exe`},
		{"already absolute", `C:\Users\me\app.exe`, `C:\Users\me\app.exe`},
		{"unresolved guid", `{00000000-0000-0000-0000-000000000000}\x.exe`, ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeUserAssistPath(tc.in, roots); got != tc.want {
				t.Errorf("normalizeUserAssistPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseUserAssist(t *testing.T) {
	roots := map[string]string{
		"{6d809377-6af0-444b-8957-a3773f02200e}": `C:\Program Files`,
	}
	want := time.Date(2025, 6, 10, 8, 42, 11, 0, time.UTC)

	records := []userAssistRecord{
		{ // valid: resolvable path with a real last-run time
			Name: rot13(`{6D809377-6AF0-444B-8957-A3773F02200E}\Git\bin\git.exe`),
			Data: base64.StdEncoding.EncodeToString(userAssistBlob(timeToFileTime(want))),
		},
		{ // skipped: never run (zero FILETIME)
			Name: rot13(`{6D809377-6AF0-444B-8957-A3773F02200E}\Never\never.exe`),
			Data: base64.StdEncoding.EncodeToString(userAssistBlob(0)),
		},
		{ // skipped: legacy/short blob without a timestamp field
			Name: rot13(`{6D809377-6AF0-444B-8957-A3773F02200E}\Old\old.exe`),
			Data: base64.StdEncoding.EncodeToString(make([]byte, 16)),
		},
		{ // skipped: GUID prefix we do not resolve
			Name: rot13(`{00000000-0000-0000-0000-000000000000}\x.exe`),
			Data: base64.StdEncoding.EncodeToString(userAssistBlob(timeToFileTime(want))),
		},
	}
	raw, err := json.Marshal(records)
	if err != nil {
		t.Fatalf("marshal records: %v", err)
	}

	entries := parseUserAssist(raw, roots)
	if len(entries) != 1 {
		t.Fatalf("parseUserAssist returned %d entries, want 1", len(entries))
	}
	if !entries[0].LastRun.Equal(want) {
		t.Errorf("LastRun = %v, want %v", entries[0].LastRun, want)
	}
	if wantPath := strings.ToLower(`C:\Program Files\Git\bin\git.exe`); entries[0].Path != wantPath {
		t.Errorf("Path = %q, want %q", entries[0].Path, wantPath)
	}
}

func TestParseUserAssist_EmptyOrGarbage(t *testing.T) {
	if entries := parseUserAssist(nil, nil); entries != nil {
		t.Errorf("parseUserAssist(nil) = %v, want nil", entries)
	}
	if entries := parseUserAssist([]byte("not json"), nil); entries != nil {
		t.Errorf("parseUserAssist(garbage) = %v, want nil", entries)
	}
}

func TestApplyLastOpened(t *testing.T) {
	last := time.Date(2025, 6, 10, 8, 42, 11, 0, time.UTC)
	earlier := last.Add(-48 * time.Hour)

	entries := []lastOpenedEntry{
		{Path: `c:\program files\git\bin\git.exe`, LastRun: earlier},
		{Path: `c:\program files\git\cmd\git.exe`, LastRun: last}, // most recent under Git
		{Path: `c:\program files\other\other.exe`, LastRun: last},
	}

	software := []SoftwareInfo{
		{Name: "Git", FilePath: `C:\Program Files\Git`},
		{Name: "NoInstallLoc", FilePath: ""},
		{Name: "Unmatched", FilePath: `C:\Program Files\Nope`},
	}
	applyLastOpened(software, entries)

	if got := software[0].LastOpened; got != last.UTC().Format(time.RFC3339) {
		t.Errorf("Git.LastOpened = %q, want %q", got, last.UTC().Format(time.RFC3339))
	}
	if software[1].LastOpened != "" {
		t.Errorf("NoInstallLoc.LastOpened = %q, want empty", software[1].LastOpened)
	}
	if software[2].LastOpened != "" {
		t.Errorf("Unmatched.LastOpened = %q, want empty", software[2].LastOpened)
	}
}

func TestKnownFolderRoots_FromEnvironment(t *testing.T) {
	t.Setenv("ProgramFiles", `D:\PF`)
	t.Setenv("ProgramFiles(x86)", `D:\PF86`)
	t.Setenv("windir", `D:\Win`)

	roots := knownFolderRoots()
	want := map[string]string{
		"{6d809377-6af0-444b-8957-a3773f02200e}": `D:\PF`,
		"{905e63b6-c1bf-494e-b29c-65b732d3d21a}": `D:\PF`,
		"{7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e}": `D:\PF86`,
		"{f38bf404-1d43-42f2-9305-67de0b28fc23}": `D:\Win`,
		"{1ac14e77-02e7-4e5d-b744-2eb1ae5198b7}": `D:\Win\System32`,
	}
	if len(roots) != len(want) {
		t.Fatalf("roots has %d entries, want %d: %v", len(roots), len(want), roots)
	}
	for k, v := range want {
		if roots[k] != v {
			t.Errorf("roots[%s] = %q, want %q", k, roots[k], v)
		}
	}
}

// With the environment variables unset (empty), the documented defaults apply.
func TestKnownFolderRoots_Defaults(t *testing.T) {
	t.Setenv("ProgramFiles", "")
	t.Setenv("ProgramFiles(x86)", "")
	t.Setenv("windir", "")

	roots := knownFolderRoots()
	checks := map[string]string{
		"{905e63b6-c1bf-494e-b29c-65b732d3d21a}": `C:\Program Files`,
		"{7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e}": `C:\Program Files (x86)`,
		"{1ac14e77-02e7-4e5d-b744-2eb1ae5198b7}": `C:\Windows\System32`,
	}
	for k, v := range checks {
		if roots[k] != v {
			t.Errorf("roots[%s] = %q, want %q", k, roots[k], v)
		}
	}
}

// TestGetWindowsLastOpened_LiveIsWellFormed runs the real (read-only) UserAssist
// query. Its contents depend on the machine, so only the shape is asserted: the
// call must not fail hard, and every entry it does return must be normalized.
func TestGetWindowsLastOpened_LiveIsWellFormed(t *testing.T) {
	for _, e := range getWindowsLastOpened() {
		if e.Path == "" || e.Path != strings.ToLower(e.Path) {
			t.Errorf("entry path %q is empty or not lowercased", e.Path)
		}
		if e.LastRun.IsZero() || e.LastRun.Location() != time.UTC {
			t.Errorf("entry %q has invalid LastRun %v", e.Path, e.LastRun)
		}
	}
}
