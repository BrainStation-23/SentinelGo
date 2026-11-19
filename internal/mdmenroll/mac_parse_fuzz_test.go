package mdmenroll

import (
	"testing"
)

// The ioreg and version parsers read OS output the agent doesn't control:
// they must never panic, and a lock or idle reading is only ever reported
// with ok.

func FuzzConsoleLocked(f *testing.F) {
	f.Add(consoleUsers("false", consoleUser("501", true, "")), "501")
	f.Add(consoleUsers("true", consoleUser("501", true, "true"), consoleUser("502", false, "")), "502")
	f.Add(`<?xml version="1.0"?><plist><dict><key>IOConsoleUsers</key><array><dict><key>kCGSSessionUserIDKey</key><string>501</string></dict></array></dict></plist>`, "501")
	f.Add(`<plist><dict><key>IOConsoleUsers</key><string>x</string></dict></plist>`, "501")
	f.Add(`<plist><dict><key>IOConsoleUsers</key><array><dict>`, "501")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, out, uid string) {
		if locked, ok := consoleLocked(out, uid); locked && !ok {
			t.Errorf("locked without ok")
		}
		_ = macUserActive(out, out, uid)
	})
}

func FuzzHIDIdle(f *testing.F) {
	f.Add(`<?xml version="1.0"?><plist version="1.0"><array><dict><key>HIDIdleTime</key><integer>262067422291</integer></dict></array></plist>`)
	f.Add(`<plist><array><dict><key>HIDIdleTime</key><integer>-1</integer></dict></array></plist>`)
	f.Add(`<plist><array><dict><key>HIDIdleTime</key><string>NaN</string></dict></array></plist>`)
	f.Add(`<plist><array><dict><key>HIDIdleTime</key><real>1e300</real></dict></array></plist>`)
	f.Add(`<plist><dict><key>HIDIdleTime</key><integer>5</integer></dict></plist>`)
	f.Add(`<plist><array><string>x</string></array></plist>`)
	f.Add("")
	f.Fuzz(func(t *testing.T, out string) {
		if d, ok := hidIdle(out); d < 0 || (!ok && d != 0) {
			t.Errorf("hidIdle = %v %v", d, ok)
		}
	})
}

func FuzzMacMajor(f *testing.F) {
	for _, s := range []string{"15.1", "12.7.6", "26.0.1", "", "x", "-3.0", "99999999999999999999.1", " 14 "} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		if n := macMajor(v); n < 0 {
			t.Errorf("macMajor(%q) = %d", v, n)
		}
		if p := installPane(macMajor(v)); p != deviceManagementPane && p != profilesPrefPane {
			t.Errorf("installPane = %q", p)
		}
	})
}
