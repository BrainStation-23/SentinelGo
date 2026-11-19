package mdmenroll

import (
	"strings"
	"testing"
	"time"
)

// consoleUsers is `ioreg -n Root -d1 -a`, cut to what consoleLocked reads.
func consoleUsers(consoleLocked string, users ...string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>IOConsoleLocked</key>
	<` + consoleLocked + `/>
	<key>IOConsoleUsers</key>
	<array>` + strings.Join(users, "") + `</array>
	<key>IOKitBuildVersion</key>
	<string>Darwin Kernel Version 24.1.0</string>
</dict>
</plist>`
}

func consoleUser(uid string, onConsole bool, screenLocked string) string {
	on := "false"
	if onConsole {
		on = "true"
	}
	s := `<dict>
		<key>kCGSSessionOnConsoleKey</key><` + on + `/>
		<key>kCGSSessionUserIDKey</key><integer>` + uid + `</integer>
		<key>kCGSSessionUserNameKey</key><string>u` + uid + `</string>`
	if screenLocked != "" {
		s += `<key>CGSSessionScreenIsLocked</key><` + screenLocked + `/>`
	}
	return s + `</dict>`
}

func TestConsoleLocked(t *testing.T) {
	for _, tc := range []struct {
		name         string
		out, uid     string
		locked, isOK bool
	}{
		{"unlocked", consoleUsers("false", consoleUser("501", true, "")), "501", false, true},
		{"screen locked", consoleUsers("false", consoleUser("501", true, "true")), "501", true, true},
		{"console locked", consoleUsers("true", consoleUser("501", true, "")), "501", true, true},
		{"other user locked", consoleUsers("false", consoleUser("502", false, "true"), consoleUser("501", true, "")), "501", false, true},
		{"switched out", consoleUsers("false", consoleUser("501", false, "")), "501", false, false},
		{"no entry", consoleUsers("false", consoleUser("502", true, "")), "501", false, false},
		{"not a plist", "ioreg: error", "501", false, false},
		{"an empty array", `<plist><array/></plist>`, "501", false, false},
		{"array-wrapped, locked", strings.Replace(strings.Replace(consoleUsers("false", consoleUser("501", true, "true")), "<dict>", "<array><dict>", 1), "</dict>\n</plist>", "</dict></array>\n</plist>", 1), "501", true, true},
	} {
		locked, ok := consoleLocked(tc.out, tc.uid)
		if locked != tc.locked || ok != tc.isOK {
			t.Errorf("%s: locked %v ok %v, want %v %v", tc.name, locked, ok, tc.locked, tc.isOK)
		}
	}
}

func TestHIDIdle(t *testing.T) {
	hid := func(v string) string {
		return `<?xml version="1.0"?><plist version="1.0"><array><dict>
			<key>IOClass</key><string>IOHIDSystem</string>` + v + `</dict></array></plist>`
	}
	for _, tc := range []struct {
		out  string
		want time.Duration
		ok   bool
	}{
		{hid(`<key>HIDIdleTime</key><integer>262067422291</integer>`), 262067422291, true},
		{hid(`<key>HIDIdleTime</key><integer>0</integer>`), 0, true},
		{hid(`<key>HIDIdleTime</key><integer>-5</integer>`), 0, false},
		{hid(``), 0, false},
		{`<plist><dict><key>HIDIdleTime</key><integer>1000</integer></dict></plist>`, 1000, true},
		{"", 0, false},
	} {
		got, ok := hidIdle(tc.out)
		if got != tc.want || ok != tc.ok {
			t.Errorf("hidIdle(%.60q) = %v %v, want %v %v", tc.out, got, ok, tc.want, tc.ok)
		}
	}
}

func TestInstallPane(t *testing.T) {
	for v, want := range map[string]string{
		"15.1":   deviceManagementPane,
		"13.0":   deviceManagementPane,
		"12.7.6": profilesPrefPane,
		"11.2":   profilesPrefPane,
		"":       deviceManagementPane,
		"x":      deviceManagementPane,
	} {
		if got := installPane(macMajor(v)); got != want {
			t.Errorf("%q: %s, want %s", v, got, want)
		}
	}
}

func TestMacUserActive(t *testing.T) {
	unlocked := consoleUsers("false", consoleUser("501", true, ""))
	locked := consoleUsers("false", consoleUser("501", true, "true"))
	hid := func(ns string) string {
		return `<plist><array><dict><key>HIDIdleTime</key><integer>` + ns + `</integer></dict></array></plist>`
	}
	for _, tc := range []struct {
		name      string
		root, hid string
		want      bool
	}{
		{"at the Mac", unlocked, hid("5000000000"), true},
		{"screen locked", locked, hid("0"), false},
		{"screen locked, array-wrapped", "<plist><array>" + strings.TrimSuffix(strings.SplitN(locked, "<plist version=\"1.0\">", 2)[1], "</plist>") + "</array></plist>", hid("0"), false},
		{"idle", unlocked, hid("600000000000"), false},
		{"nothing readable", "", "", true},
	} {
		if got := macUserActive(tc.root, tc.hid, "501"); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
