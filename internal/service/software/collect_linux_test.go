//go:build linux

package software

import (
	"strings"
	"testing"
)

func TestParseDebPackages(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantNames []string
	}{
		{name: "empty", input: "", wantNames: nil},
		{name: "blank lines skipped", input: "\n\n", wantNames: nil},
		{
			name:      "single package",
			input:     "curl,7.88.1\n",
			wantNames: []string{"curl"},
		},
		{
			name:      "package with size field",
			input:     "bash,5.2.15,2348\n",
			wantNames: []string{"bash"},
		},
		{
			name:      "multiple packages",
			input:     "curl,7.88.1\nbash,5.2.15\n",
			wantNames: []string{"curl", "bash"},
		},
		{
			name:      "line with fewer than 2 fields skipped",
			input:     "incomplete\ncurl,7.88.1\n",
			wantNames: []string{"curl"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []SoftwareInfo
			parseDebPackages([]byte(tc.input), &got)
			if len(got) != len(tc.wantNames) {
				t.Fatalf("got %d packages, want %d", len(got), len(tc.wantNames))
			}
			for i, s := range got {
				if s.Name != tc.wantNames[i] {
					t.Errorf("[%d] Name = %q, want %q", i, s.Name, tc.wantNames[i])
				}
				if s.Source != "deb_packages" {
					t.Errorf("[%d] Source = %q, want deb_packages", i, s.Source)
				}
				if s.InstalledVersion != strings.Split(tc.input, "\n")[i] && s.InstalledVersion == "" {
					t.Errorf("[%d] InstalledVersion is empty", i)
				}
				if !s.IsActive {
					t.Errorf("[%d] IsActive = false, want true", i)
				}
			}
		})
	}
}

func TestParseRPMPackages(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantNames []string
		wantVers  []string
	}{
		{name: "empty", input: "", wantNames: nil},
		{
			name:      "single package without timestamp",
			input:     "bash 5.2.15 2048\n",
			wantNames: []string{"bash"},
			wantVers:  []string{"5.2.15"},
		},
		{
			name:      "package with unix timestamp",
			input:     "curl 7.88.1 512 1700000000\n",
			wantNames: []string{"curl"},
			wantVers:  []string{"7.88.1"},
		},
		{
			name:      "line with fewer than 2 fields skipped",
			input:     "only-one\ncurl 7.88.1 512\n",
			wantNames: []string{"curl"},
			wantVers:  []string{"7.88.1"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []SoftwareInfo
			parseRPMPackages([]byte(tc.input), &got)
			if len(got) != len(tc.wantNames) {
				t.Fatalf("got %d packages, want %d", len(got), len(tc.wantNames))
			}
			for i, s := range got {
				if s.Name != tc.wantNames[i] {
					t.Errorf("[%d] Name = %q, want %q", i, s.Name, tc.wantNames[i])
				}
				if s.InstalledVersion != tc.wantVers[i] {
					t.Errorf("[%d] InstalledVersion = %q, want %q", i, s.InstalledVersion, tc.wantVers[i])
				}
				if s.Source != "rpm_packages" {
					t.Errorf("[%d] Source = %q, want rpm_packages", i, s.Source)
				}
			}
		})
	}
}

func TestParseSnapPackages(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantNames []string
	}{
		{name: "empty", input: "", wantNames: nil},
		{
			name:      "header line skipped",
			input:     "Name  Version  Rev  Tracking  Publisher  Notes\n",
			wantNames: nil,
		},
		{
			name:      "single package",
			input:     "core20 20230801 2015 latest/stable canonical -\n",
			wantNames: []string{"core20"},
		},
		{
			name:      "line with fewer than 2 fields skipped",
			input:     "onlyone\ncore20 20230801 2015 latest/stable canonical -\n",
			wantNames: []string{"core20"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []SoftwareInfo
			parseSnapPackages([]byte(tc.input), &got)
			if len(got) != len(tc.wantNames) {
				t.Fatalf("got %d packages, want %d", len(got), len(tc.wantNames))
			}
			for i, s := range got {
				if s.Name != tc.wantNames[i] {
					t.Errorf("[%d] Name = %q, want %q", i, s.Name, tc.wantNames[i])
				}
				if s.Source != "snap_packages" {
					t.Errorf("[%d] Source = %q, want snap_packages", i, s.Source)
				}
			}
		})
	}
}

func TestParseFlatpakPackages(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantNames []string
	}{
		{name: "empty", input: "", wantNames: nil},
		{
			name:      "header skipped",
			input:     "application name version origin\n",
			wantNames: nil,
		},
		{
			name:      "single package",
			input:     "org.gnome.Calculator Calculator 45.0 flathub\n",
			wantNames: []string{"Calculator"},
		},
		{
			name:      "fewer than 3 fields skipped",
			input:     "org.gnome.Short\norg.gnome.Calculator Calculator 45.0 flathub\n",
			wantNames: []string{"Calculator"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []SoftwareInfo
			parseFlatpakPackages([]byte(tc.input), &got)
			if len(got) != len(tc.wantNames) {
				t.Fatalf("got %d packages, want %d", len(got), len(tc.wantNames))
			}
			for i, s := range got {
				if s.Name != tc.wantNames[i] {
					t.Errorf("[%d] Name = %q, want %q", i, s.Name, tc.wantNames[i])
				}
				if s.Source != "flatpak_packages" {
					t.Errorf("[%d] Source = %q, want flatpak_packages", i, s.Source)
				}
			}
		})
	}
}

func TestLinuxExtDirGlobs(t *testing.T) {
	home := "/home/user"

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
