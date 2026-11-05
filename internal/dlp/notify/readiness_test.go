package notify

import "testing"

func u32(v uint32) *uint32 { return &v }
func bptr(v bool) *bool    { return &v }

func TestWinReadiness(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    winSettings
		want string
	}{
		{"nothing set", winSettings{QUNS: 5}, ReadySupported},
		{"query failed", winSettings{}, ReadySupported},
		{"policy wins", winSettings{PolicyNoToast: u32(1), ToastEnabled: u32(0), QUNS: 5}, ReadyDisabledPolicy},
		{"policy off", winSettings{PolicyNoToast: u32(0), QUNS: 5}, ReadySupported},
		{"all off", winSettings{ToastEnabled: u32(0), QUNS: 5}, ReadyDisabledGlobal},
		{"app off", winSettings{ToastEnabled: u32(1), AppEnabled: u32(0), QUNS: 5}, ReadyDisabledApp},
		{"full screen", winSettings{QUNS: 2}, ReadyDND},
		{"presentation", winSettings{QUNS: 4}, ReadyDND},
		{"quiet time", winSettings{QUNS: 6}, ReadyDND},
		{"no desktop", winSettings{QUNS: 1}, "unavailable:no_desktop"},
		{"off beats dnd", winSettings{ToastEnabled: u32(0), QUNS: 2}, ReadyDisabledGlobal},
	} {
		if got, _ := winReadiness(tc.s); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestDarwinReadiness(t *testing.T) {
	const bundle = "com.apple.ScriptEditor2"
	nc := []byte(`{"apps":[{"bundle-id":"com.apple.Safari","flags":41951246},{"bundle-id":"com.apple.ScriptEditor2","flags":41951246}]}`)
	off := []byte(`{"apps":[{"bundle-id":"com.apple.ScriptEditor2","flags":8401166}]}`) // bit 25 clear
	for _, tc := range []struct {
		name    string
		nc      []byte
		managed *bool
		want    string
	}{
		{"allowed", nc, nil, ReadySupported},
		{"app off", off, nil, ReadyDisabledApp},
		{"mdm off", nc, bptr(false), ReadyDisabledPolicy},
		{"mdm on, user off", off, bptr(true), ReadyDisabledApp},
		{"unreadable", nil, nil, ReadyUnknown},
		{"junk", []byte("{"), nil, ReadyUnknown},
		{"not registered", []byte(`{"apps":[]}`), nil, ReadyUnknown},
	} {
		if got, _ := darwinReadiness(tc.nc, bundle, tc.managed); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	m := managedNotificationEnabled([]byte(`{"NotificationSettings":[{"BundleIdentifier":"x"},{"BundleIdentifier":"com.apple.ScriptEditor2","NotificationsEnabled":false}]}`), bundle)
	if m == nil || *m {
		t.Fatalf("managed %v", m)
	}
	if managedNotificationEnabled([]byte(`{}`), bundle) != nil {
		t.Fatal("managed setting invented")
	}
}

func TestLinuxReadiness(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    linuxSettings
		want string
	}{
		{"ok", linuxSettings{ToolFound: true, ServerOwned: bptr(true), ShowBanners: "true\n", Inhibited: bptr(false)}, ReadySupported},
		{"no tool", linuxSettings{ServerOwned: bptr(true)}, "unavailable:no_tool"},
		{"no server", linuxSettings{ToolFound: true, ServerOwned: bptr(false)}, "unavailable:no_server"},
		{"gnome dnd", linuxSettings{ToolFound: true, ServerOwned: bptr(true), ShowBanners: "false\n"}, ReadyDND},
		{"kde dnd", linuxSettings{ToolFound: true, ServerOwned: bptr(true), Inhibited: bptr(true)}, ReadyDND},
		{"no bus", linuxSettings{ToolFound: true}, ReadyUnknown},
	} {
		if got, _ := linuxReadiness(tc.s); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	for in, want := range map[string]*bool{"b true\n": bptr(true), "(false,)\n": bptr(false), "(<true>,)": bptr(true), "garbage": nil} {
		got := parseBusctlBool(in)
		if (got == nil) != (want == nil) || (got != nil && *got != *want) {
			t.Errorf("%q: %v", in, got)
		}
	}
}

func TestShows(t *testing.T) {
	for state, want := range map[string]bool{ReadySupported: true, ReadyDND: true, ReadyUnknown: true, "": true,
		ReadyDisabledApp: false, ReadyDisabledGlobal: false, ReadyDisabledPolicy: false, "unavailable:no_server": false} {
		if Shows(state) != want {
			t.Errorf("%q: %v", state, !want)
		}
	}
}
