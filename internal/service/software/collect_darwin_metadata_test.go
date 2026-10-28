//go:build darwin

package software

import (
	"errors"
	"strings"
	"testing"
)

func TestParseSystemProfilerAppsMetadata(t *testing.T) {
	input := `{"SPApplicationsDataType":[
		{"_name":"Safari","version":"17.0","path":"/Applications/Safari.app","obtained_from":"apple","arch_kind":"arch_arm_i64","signed_by":["Software Signing","Apple Code Signing Certification Authority","Apple Root CA"]},
		{"_name":"Google Chrome","version":"130.0","path":"/Applications/Google Chrome.app","obtained_from":"identified_developer","arch_kind":"arch_arm_i64","signed_by":["Developer ID Application: Google LLC (EQHXZ8M8AV)","Developer ID Certification Authority","Apple Root CA"]},
		{"_name":"Xcode","version":"15.0","path":"/Applications/Xcode.app","obtained_from":"mac_app_store","arch_kind":"arch_arm","signed_by":["Apple Mac OS Application Signing","Apple Worldwide Developer Relations Certification Authority","Apple Root CA"]},
		{"_name":"Unsigned","version":"1.0","path":"/Applications/Unsigned.app","obtained_from":"unknown"}
	]}`
	var got []SoftwareInfo
	if !parseSystemProfilerApps([]byte(input), &got) {
		t.Fatal("parse failed")
	}
	assertKnownSource(t, got)
	want := []struct{ publisher, arch string }{
		{"Apple Inc.", "universal"},
		{"Google LLC", "universal"},
		{"", "arm64"}, // App Store apps are re-signed by Apple
		{"", ""},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d apps, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Publisher != w.publisher || got[i].Architecture != w.arch {
			t.Errorf("%s: publisher=%q arch=%q, want %q %q", got[i].Name, got[i].Publisher, got[i].Architecture, w.publisher, w.arch)
		}
	}
}

func TestParseMdlsRaw(t *testing.T) {
	paths := []string{"/Applications/Safari.app", "/Applications/Never Opened.app"}
	out := strings.Join([]string{
		"2025-06-10 08:42:11 +0000", "2024-01-02 03:04:05 +0000", "123456789", "com.apple.Safari",
		"(null)", "(null)", "(null)", "(null)",
	}, "\x00")

	result := map[string]bundleMeta{}
	if !parseMdlsRaw([]byte(out), paths, result) {
		t.Fatal("parseMdlsRaw rejected well-formed output")
	}
	safari := result[paths[0]]
	if safari.LastUsed != "2025-06-10T08:42:11Z" || safari.DateAdded != "2024-01-02T03:04:05Z" ||
		safari.Size != 123456789 || safari.BundleID != "com.apple.Safari" {
		t.Errorf("Safari = %+v", safari)
	}
	if never := result[paths[1]]; never != (bundleMeta{}) {
		t.Errorf("(null) attributes must be left out, got %+v", never)
	}

	// A trailing separator is tolerated.
	result = map[string]bundleMeta{}
	if !parseMdlsRaw([]byte(out+"\x00"), paths, result) {
		t.Error("parseMdlsRaw rejected output with a trailing NUL")
	}

	// Newline-separated output (no NUL at all) is parsed the same way.
	result = map[string]bundleMeta{}
	if !parseMdlsRaw([]byte(strings.ReplaceAll(out, "\x00", "\n")+"\n"), paths, result) {
		t.Fatal("parseMdlsRaw rejected newline-separated output")
	}
	if result[paths[0]] != safari {
		t.Errorf("newline-separated Safari = %+v, want %+v", result[paths[0]], safari)
	}

	// A value count that does not match cannot be attributed and is dropped.
	result = map[string]bundleMeta{}
	if parseMdlsRaw([]byte("(null)\x00(null)"), paths, result) || len(result) != 0 {
		t.Errorf("mismatched value count must be rejected, got %v", result)
	}
}

func TestApplyBundleMeta(t *testing.T) {
	apps := []SoftwareInfo{{Name: "Safari", FilePath: "/Applications/Safari.app"}, {Name: "Other", FilePath: "/x.app"}}
	applyBundleMeta(apps, map[string]bundleMeta{
		"/Applications/Safari.app": {LastUsed: "2025-06-10T08:42:11Z", DateAdded: "2024-01-02T03:04:05Z", Size: 42, BundleID: "com.apple.Safari"},
	})
	s := apps[0]
	if s.LastOpened != "2025-06-10T08:42:11Z" || s.InstallDate != "2024-01-02T03:04:05Z" || s.SizeBytes != 42 || s.BundleID != "com.apple.Safari" {
		t.Errorf("Safari = %+v", s)
	}
	if o := apps[1]; o.InstallDate != "" || o.BundleID != "" {
		t.Errorf("Other should be untouched, got %+v", o)
	}
}

func TestParseHomebrewInfo(t *testing.T) {
	input := `{"formulae":[
		{"name":"git","tap":"homebrew/core","installed":[{"version":"2.42.0","time":1690000000},{"version":"2.43.0","time":1700000000}]},
		{"name":"orphan","tap":null,"installed":[]}
	],"casks":[
		{"token":"docker","tap":"homebrew/cask","installed":"24.0.7","installed_time":1710000000}
	]}`
	formulae, casks := parseHomebrewInfo([]byte(input))
	if g := formulae["git"]; g.Tap != "homebrew/core" || g.InstallDate != "2023-11-14T22:13:20Z" {
		t.Errorf("git = %+v", g)
	}
	if o := formulae["orphan"]; o != (brewMeta{}) {
		t.Errorf("orphan should have no metadata, got %+v", o)
	}
	if d := casks["docker"]; d.Tap != "homebrew/cask" || d.InstallDate != "2024-03-09T16:00:00Z" {
		t.Errorf("docker = %+v", d)
	}

	if f, c := parseHomebrewInfo([]byte("not json")); f != nil || c != nil {
		t.Error("invalid JSON must yield nil maps")
	}

	pkgs := []SoftwareInfo{{Name: "git", Source: sourceHomebrew}, {Name: "unknown", Source: sourceHomebrew}}
	applyHomebrewInfo(pkgs, formulae)
	assertKnownSource(t, pkgs)
	if pkgs[0].Publisher != "homebrew/core" || pkgs[0].InstallDate == "" || pkgs[1].Publisher != "" {
		t.Errorf("applyHomebrewInfo = %+v", pkgs)
	}
}

func TestMacPublisher(t *testing.T) {
	cases := []struct {
		from     string
		signedBy []string
		want     string
	}{
		{"apple", nil, "Apple Inc."},
		{"identified_developer", []string{"Software Signing"}, "Apple Inc."},
		{"identified_developer", []string{"Developer ID Application: Slack Technologies, Inc. (BQR82RBBHL)"}, "Slack Technologies, Inc."},
		{"identified_developer", []string{"Developer ID Application: Jane Doe"}, "Jane Doe"},
		{"mac_app_store", []string{"Apple Mac OS Application Signing"}, ""},
		{"unknown", nil, ""},
	}
	for _, c := range cases {
		if got := macPublisher(c.from, c.signedBy); got != c.want {
			t.Errorf("macPublisher(%q, %v) = %q, want %q", c.from, c.signedBy, got, c.want)
		}
	}
}

func TestFillBundleIDsFromInfoPlist(t *testing.T) {
	// Two apps in one mdls batch: Spotlight off (null bundle ID) for Slack,
	// indexed for Safari. A third app's batch failed, so it has no metadata.
	paths := []string{"/Applications/Slack.app", "/Applications/Safari.app"}
	meta := map[string]bundleMeta{}
	out := "(null)\x00(null)\x00(null)\x00(null)\x00" +
		"(null)\x00(null)\x0012345\x00com.apple.Safari"
	if !parseMdlsRaw([]byte(out), paths, meta) {
		t.Fatal("parseMdlsRaw failed")
	}
	apps := []SoftwareInfo{
		{Name: "Slack", FilePath: "/Applications/Slack.app"},
		{Name: "Safari", FilePath: "/Applications/Safari.app"},
		{Name: "Xcode", FilePath: "/Applications/Xcode.app"},
		{Name: "Broken", FilePath: "/Applications/Broken.app"},
		{Name: "No path"},
	}
	applyBundleMeta(apps, meta)

	var calls []string
	run := func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		switch args[len(args)-1] {
		case "/Applications/Slack.app/Contents/Info.plist":
			return []byte("com.tinyspeck.slackmacgap\n"), nil
		case "/Applications/Xcode.app/Contents/Info.plist":
			return []byte("com.apple.dt.Xcode\n"), nil
		}
		return nil, errors.New("exit status 1")
	}
	fillBundleIDsFromInfoPlist(apps, run)

	want := map[string]string{
		"Slack":   "com.tinyspeck.slackmacgap",
		"Safari":  "com.apple.Safari",
		"Xcode":   "com.apple.dt.Xcode",
		"Broken":  "",
		"No path": "",
	}
	for _, a := range apps {
		if a.BundleID != want[a.Name] {
			t.Errorf("%s: BundleID = %q, want %q", a.Name, a.BundleID, want[a.Name])
		}
	}
	if len(calls) != 3 {
		t.Fatalf("plutil calls = %d, want 3 (Safari already has an ID, No path has none): %v", len(calls), calls)
	}
	if calls[0] != "plutil -extract CFBundleIdentifier raw -o - /Applications/Slack.app/Contents/Info.plist" {
		t.Errorf("first call = %q", calls[0])
	}
}
