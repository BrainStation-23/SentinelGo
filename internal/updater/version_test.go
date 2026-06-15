package updater

import "testing"

func TestIsNewerVersion(t *testing.T) {
	cases := []struct {
		candidate, current string
		want               bool
		wantErr            bool
	}{
		{"v2.1.6", "v2.1.5", true, false},     // patch bump
		{"v2.2.0", "v2.1.5", true, false},     // minor bump
		{"v3.0.0", "v2.9.9", true, false},     // major bump
		{"v2.1.5", "v2.1.5", false, false},    // equal -> not newer
		{"v2.1.4", "v2.1.5", false, false},    // older -> downgrade blocked
		{"2.1.6", "2.1.5", true, false},       // no leading v
		{"v2.1.6-rc1", "v2.1.5", true, false}, // pre-release suffix ignored
		{"v2.2", "v2.1.9", true, false},       // missing patch defaults to 0
		{"dev", "v2.1.5", false, true},        // unparseable candidate
		{"v2.1.6", "dev", false, true},        // unparseable current (dev build)
	}

	for _, tc := range cases {
		got, err := isNewerVersion(tc.candidate, tc.current)
		if (err != nil) != tc.wantErr {
			t.Errorf("isNewerVersion(%q,%q) err=%v, wantErr=%v", tc.candidate, tc.current, err, tc.wantErr)
			continue
		}
		if err == nil && got != tc.want {
			t.Errorf("isNewerVersion(%q,%q) = %v, want %v", tc.candidate, tc.current, got, tc.want)
		}
	}
}
