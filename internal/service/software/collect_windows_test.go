//go:build windows

package software

import (
	"strings"
	"testing"
)

func TestParsePowerShellOutput(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		source    string
		wantNames []string
		wantOK    bool
	}{
		{name: "empty/invalid JSON", input: "", source: "programs", wantNames: nil, wantOK: false},
		{name: "non-JSON garbage", input: "powershell error text", source: "programs", wantNames: nil, wantOK: false},
		{
			name:      "single item as object (not array)",
			input:     `{"Name":"Git","Version":"2.43.0","InstallLocation":"C:\\Program Files\\Git","InstallDate":""}`,
			source:    "programs",
			wantNames: []string{"Git"},
			wantOK:    true,
		},
		{
			name:      "array of items",
			input:     `[{"Name":"Git","Version":"2.43.0","InstallLocation":"C:\\Program Files\\Git","InstallDate":""},{"Name":"Notepad++","Version":"8.6.2","InstallLocation":"","InstallDate":""}]`,
			source:    "programs",
			wantNames: []string{"Git", "Notepad++"},
			wantOK:    true,
		},
		{
			name:      "empty array is a valid (successful) scan",
			input:     `[]`,
			source:    "programs",
			wantNames: nil,
			wantOK:    true,
		},
		{
			name:      "item without Name field skipped",
			input:     `[{"Version":"1.0","InstallLocation":"","InstallDate":""},{"Name":"Git","Version":"2.43.0","InstallLocation":"","InstallDate":""}]`,
			source:    "programs",
			wantNames: []string{"Git"},
			wantOK:    true,
		},
		{
			name:      "install date parsed from yyyyMMdd format",
			input:     `[{"Name":"VSCode","Version":"1.85","InstallLocation":"","InstallDate":"20231201"}]`,
			source:    "programs",
			wantNames: []string{"VSCode"},
			wantOK:    true,
		},
		{
			name:      "invalid install date falls back to now",
			input:     `[{"Name":"App","Version":"1.0","InstallLocation":"","InstallDate":"not-a-date"}]`,
			source:    "programs",
			wantNames: []string{"App"},
			wantOK:    true,
		},
		{
			name:      "windows store source",
			input:     `[{"Name":"Microsoft.WindowsCalculator","Version":"11.2311.0.0","InstallLocation":"C:\\Program Files"}]`,
			source:    "microsoft_store",
			wantNames: []string{"Microsoft.WindowsCalculator"},
			wantOK:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []SoftwareInfo
			if ok := parsePowerShellOutput([]byte(tc.input), &got, tc.source); ok != tc.wantOK {
				t.Errorf("parsePowerShellOutput ok = %v, want %v", ok, tc.wantOK)
			}
			if len(got) != len(tc.wantNames) {
				t.Fatalf("got %d packages, want %d", len(got), len(tc.wantNames))
			}
			for i, s := range got {
				if s.Name != tc.wantNames[i] {
					t.Errorf("[%d] Name = %q, want %q", i, s.Name, tc.wantNames[i])
				}
				if s.Source != tc.source {
					t.Errorf("[%d] Source = %q, want %q", i, s.Source, tc.source)
				}
				if !s.IsActive {
					t.Errorf("[%d] IsActive = false", i)
				}
			}
		})
	}
}

func TestWindowsExtDirGlobs(t *testing.T) {
	home := `C:\Users\testuser`

	chrome := chromeExtDirGlobs(home)
	if len(chrome) == 0 {
		t.Error("chromeExtDirGlobs returned empty slice")
	}
	for _, p := range chrome {
		if !strings.HasPrefix(p, home) {
			t.Errorf("chromeExtDirGlobs: path %q does not start with home dir", p)
		}
	}

	edge := edgeExtDirGlobs(home)
	if len(edge) == 0 {
		t.Error("edgeExtDirGlobs returned empty slice")
	}

	brave := braveExtDirGlobs(home)
	if len(brave) == 0 {
		t.Error("braveExtDirGlobs returned empty slice")
	}

	firefox := firefoxProfileGlobs(home)
	if len(firefox) == 0 {
		t.Error("firefoxProfileGlobs returned empty slice")
	}
}
