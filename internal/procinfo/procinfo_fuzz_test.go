package procinfo

// Fuzz target for the version extractors. Only the pure string functions are
// fuzzed: parseWindowsProcessLine / parseUnixProcessLine fall back to
// *executing* the binary named in the line (resolveVersion -> GetBinaryVersion),
// so fuzzing them would run arbitrary command lines. Those are covered by
// table tests instead.
//
// The seed corpus runs as an ordinary unit test under `go test ./...`.
// To fuzz: go test -run='^$' -fuzz='^FuzzExtractVersion$' -fuzztime=1m ./internal/procinfo/

import "testing"

func FuzzExtractVersion(f *testing.F) {
	for _, s := range []string{
		`/opt/sentinelgo/sentinelgo -version=v2.1.5`,
		`C:\sentinelgo\sentinelgo.exe -version="v2.1.5" -service`,
		`sentinelgo -version v2.1.5`,
		`sentinelgo --version`,
		`sentinelgo -version=`,
		`-version=-version=`,
		`SentinelGo version v2.1.5, build abc`,
		"version\nversion",
		"",
		" ",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		_ = ExtractVersionFromCmd(s)
		_ = extractVersionFromOutput(s)
	})
}

// TestParseWindowsProcessLine_ShortRow guards the column-count check: a
// sentinelgo.exe row with fewer than 9 CSV fields used to index fields[8] and
// panic. The command line includes -version= so no binary is executed.
func TestParseWindowsProcessLine_ShortRow(t *testing.T) {
	for _, line := range []string{
		`"sentinelgo.exe","1234","Services","0","12,345 K"`,
		`"sentinelgo.exe","1234","Services","0","12 K","Running","NT AUTHORITY\SYSTEM","0:00:01"`,
	} {
		if info := parseWindowsProcessLine(line); info.PID != 0 {
			t.Errorf("parseWindowsProcessLine(%q).PID = %d, want 0 for a short row", line, info.PID)
		}
	}

	full := `"sentinelgo.exe","1234","Services","0","12 K","Running","SYSTEM","0:00:01","C:\sentinelgo\sentinelgo.exe -version=v2.1.5"`
	info := parseWindowsProcessLine(full)
	if info.PID != 1234 || info.Version != "v2.1.5" {
		t.Errorf("parseWindowsProcessLine(full row) = %+v, want PID 1234 and version v2.1.5", info)
	}
}
