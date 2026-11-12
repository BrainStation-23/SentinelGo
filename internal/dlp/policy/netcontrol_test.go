package policy

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
)

func decodeFiles(t *testing.T, raw string) FilesModule {
	t.Helper()
	var m FilesModule
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	m.normalize()
	return m
}

func TestNetworkControl_Decode(t *testing.T) {
	m := decodeFiles(t, `{"enabled": true, "network_control": {"enabled": true,
	  "blocked_apps": {"windows": [{"path": "%LOCALAPPDATA%\\Dropbox\\Client\\Dropbox.exe", "name": "Dropbox"}, "C:\\Tools\\x.exe"]},
	  "taint_block": {"enabled": true, "minutes": 15},
	  "allow_destinations": ["Files.Example.com", "*.corp.example.com", "10.1.2.3/8", "192.0.2.7", "::ffff:198.51.100.1",
	    "bad host", "fe80::1%eth0", "files.example.com", "2001:db8::/32"]}}`)
	n := m.NetworkControl
	// Taint blocks are on, so every OS's bundle controls the network; the
	// agent reports whether it can (unsupported:not_on_windows).
	if !m.ControlsNetwork("windows") || !m.ControlsNetwork("linux") {
		t.Errorf("controls network: windows %v linux %v", m.ControlsNetwork("windows"), m.ControlsNetwork("linux"))
	}
	if apps := n.BlockedApps["windows"]; len(apps) != 2 || apps[0].Name != "Dropbox" || apps[1].Path != `C:\Tools\x.exe` {
		t.Errorf("apps %+v", apps)
	}
	if n.TaintBlock.Minutes != 15 {
		t.Errorf("minutes %d", n.TaintBlock.Minutes)
	}
	want := []string{"files.example.com", "*.corp.example.com", "10.0.0.0/8", "192.0.2.7/32", "198.51.100.1/32", "2001:db8::/32"}
	if !reflect.DeepEqual(n.AllowDestinations, want) {
		t.Errorf("allow %q", n.AllowDestinations)
	}
	hosts, ranges := n.Allowed()
	if !reflect.DeepEqual(hosts, []string{"files.example.com", "*.corp.example.com"}) || len(ranges) != 4 ||
		ranges[0] != netip.MustParsePrefix("10.0.0.0/8") {
		t.Errorf("hosts %q ranges %v", hosts, ranges)
	}
}

func TestNetworkControl_Defaults(t *testing.T) {
	m := decodeFiles(t, `{"enabled": true}`)
	if m.ControlsNetwork("windows") || m.NetworkControl.TaintBlock.Minutes != DefaultTaintBlockMinutes {
		t.Errorf("absent block: %+v", m.NetworkControl)
	}
	for raw, want := range map[string]int{`0`: 10, `-3`: 10, `1`: 1, `90`: 60} {
		m := decodeFiles(t, `{"enabled": true, "network_control": {"enabled": true, "taint_block": {"enabled": true, "minutes": `+raw+`}}}`)
		if got := m.NetworkControl.TaintBlock.Minutes; got != want {
			t.Errorf("minutes %s: %d, want %d", raw, got, want)
		}
	}
	// On but with nothing to do: no control.
	if m := decodeFiles(t, `{"enabled": true, "network_control": {"enabled": true}}`); m.ControlsNetwork("windows") {
		t.Error("on with nothing to block")
	}
	// The module off turns it off.
	if m := decodeFiles(t, `{"enabled": false, "network_control": {"enabled": true, "taint_block": {"enabled": true}}}`); m.ControlsNetwork("windows") {
		t.Error("on with the module off")
	}
}

// A malformed block turns the controls off and leaves the module alone.
func TestNetworkControl_BadBlock(t *testing.T) {
	m := decodeFiles(t, `{"enabled": true, "channels": {"file.removable": true}, "network_control": {"enabled": true, "taint_block": {"enabled": "yes"}}}`)
	if m.ControlsNetwork("windows") || m.NetworkControl.DecodeError == "" || !m.Enabled || !m.Channels[ChannelFileRemovable] {
		t.Errorf("module %+v", m)
	}
}

func TestApp_MatchesExe(t *testing.T) {
	env := map[string]string{"programfiles": `C:\Program Files`}
	chrome := `C:\Program Files\Google\Chrome\Application\chrome.exe`
	slack := `C:\Users\ana\AppData\Local\slack\app-4.41.105\slack.exe`
	for _, tc := range []struct {
		app  App
		exe  string
		want bool
	}{
		{App{Name: "chrome.exe"}, chrome, true},
		{App{Name: "Chrome"}, chrome, true},
		{App{Name: "chrom"}, chrome, false},
		{App{Path: `%ProgramFiles%\Google\Chrome\Application\chrome.exe`}, chrome, true},
		{App{Path: `c:\program files\google\chrome\application\CHROME.EXE`}, chrome, true},
		{App{Path: `%LOCALAPPDATA%\slack\*\slack.exe`}, slack, true},
		{App{Path: `%LOCALAPPDATA%\slack\*\slack.exe`}, `C:\Users\ana\AppData\Local\other\slack.exe`, false},
		{App{Path: `C:\Tools\x.exe`}, `C:\Tools\x.exe.bak`, false},
		{App{Signer: "Google LLC"}, chrome, false},
		{App{Name: "chrome.exe"}, "", false},
	} {
		if got := tc.app.MatchesExe(tc.exe, env); got != tc.want {
			t.Errorf("%+v vs %s: %v", tc.app, tc.exe, got)
		}
	}
}
