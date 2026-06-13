//go:build darwin

package software

import (
	"strings"
	"testing"
)

func TestParseSystemProfilerApps(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantNames []string
		wantSrc   []string
	}{
		{
			name:      "empty/invalid JSON",
			input:     "",
			wantNames: nil,
		},
		{
			name:      "single application",
			input:     `{"SPApplicationsDataType":[{"_name":"Safari","version":"17.0","path":"/Applications/Safari.app","obtained_from":"apple","lastModified":"2023-10-01"}]}`,
			wantNames: []string{"Safari"},
			wantSrc:   []string{"applications"},
		},
		{
			name:      "mac_app_store source",
			input:     `{"SPApplicationsDataType":[{"_name":"Xcode","version":"15.0","path":"/Applications/Xcode.app","obtained_from":"mac_app_store"}]}`,
			wantNames: []string{"Xcode"},
			wantSrc:   []string{"app_store"},
		},
		{
			name:      "app with empty name skipped",
			input:     `{"SPApplicationsDataType":[{"_name":"","version":"1.0","path":"/Applications/Unknown.app","obtained_from":"apple"}]}`,
			wantNames: nil,
		},
		{
			name:      "multiple apps",
			input:     `{"SPApplicationsDataType":[{"_name":"Finder","version":"14.0","path":"/System/Library/CoreServices/Finder.app","obtained_from":"apple"},{"_name":"Terminal","version":"2.13","path":"/System/Applications/Utilities/Terminal.app","obtained_from":"apple"}]}`,
			wantNames: []string{"Finder", "Terminal"},
			wantSrc:   []string{"applications", "applications"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []SoftwareInfo
			parseSystemProfilerApps([]byte(tc.input), &got)
			if len(got) != len(tc.wantNames) {
				t.Fatalf("got %d apps, want %d", len(got), len(tc.wantNames))
			}
			for i, s := range got {
				if s.Name != tc.wantNames[i] {
					t.Errorf("[%d] Name = %q, want %q", i, s.Name, tc.wantNames[i])
				}
				if tc.wantSrc != nil && s.Source != tc.wantSrc[i] {
					t.Errorf("[%d] Source = %q, want %q", i, s.Source, tc.wantSrc[i])
				}
				if !s.IsActive {
					t.Errorf("[%d] IsActive = false", i)
				}
			}
		})
	}
}

func TestParseHomebrewPackages(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		source    string
		wantNames []string
	}{
		{name: "empty", input: "", source: "homebrew", wantNames: nil},
		{
			name:      "single package",
			input:     "git 2.43.0\n",
			source:    "homebrew",
			wantNames: []string{"git"},
		},
		{
			name:      "cask package",
			input:     "docker 24.0.7\n",
			source:    "homebrew_cask",
			wantNames: []string{"docker"},
		},
		{
			name:      "line with fewer than 2 fields skipped",
			input:     "onlyone\ngit 2.43.0\n",
			source:    "homebrew",
			wantNames: []string{"git"},
		},
		{
			name:      "multiple packages",
			input:     "git 2.43.0\ncurl 8.5.0\n",
			source:    "homebrew",
			wantNames: []string{"git", "curl"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []SoftwareInfo
			parseHomebrewPackages([]byte(tc.input), &got, tc.source)
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
			}
		})
	}
}

func TestDarwinExtDirGlobs(t *testing.T) {
	home := "/Users/testuser"

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
