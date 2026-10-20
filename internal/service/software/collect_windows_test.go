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

func TestParsePowerShellOutputMetadata(t *testing.T) {
	orig := windowsOSArch
	windowsOSArch = func() string { return "AMD64" }
	t.Cleanup(func() { windowsOSArch = orig })

	t.Run("registry program", func(t *testing.T) {
		input := `[
			{"Name":"7-Zip","Version":"26.01","InstallLocation":"C:\\Program Files\\7-Zip\\","InstallDate":"20260801","Publisher":"Igor Pavlov","EstimatedSize":5771,"Wow64":false},
			{"Name":"Etcher","Version":"2.1.6","InstallLocation":"","InstallDate":null,"Publisher":"Balena Ltd. <hello@balena.io>","EstimatedSize":null,"Wow64":true},
			{"Name":"Bare","Version":"1.0","InstallLocation":"","InstallDate":"","Publisher":null,"EstimatedSize":0,"Wow64":false}
		]`
		var got []SoftwareInfo
		if !parsePowerShellOutput([]byte(input), &got, sourcePrograms) {
			t.Fatal("parse failed")
		}
		assertKnownSource(t, got)
		if len(got) != 3 {
			t.Fatalf("got %d items, want 3", len(got))
		}
		zip := got[0]
		if zip.Publisher != "Igor Pavlov" || zip.InstallDate != "2026-08-01T00:00:00Z" ||
			zip.FirstSeenAt != zip.InstallDate || zip.SizeBytes != 5771*1024 || zip.Architecture != "x64" {
			t.Errorf("7-Zip metadata = %+v", zip)
		}
		etcher := got[1]
		if etcher.Publisher != "Balena Ltd." || etcher.InstallDate != "" || etcher.SizeBytes != 0 || etcher.Architecture != "x86" {
			t.Errorf("Etcher metadata = %+v", etcher)
		}
		bare := got[2]
		if bare.Publisher != "" || bare.InstallDate != "" || bare.SizeBytes != 0 {
			t.Errorf("Bare should have no metadata, got %+v", bare)
		}
	})

	t.Run("appx package", func(t *testing.T) {
		input := `[
			{"Name":"Microsoft.WindowsCalculator","Version":"11.2311.0.0","InstallLocation":"C:\\Program Files\\WindowsApps\\Calc","Publisher":"CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US","Architecture":"X64","InstallDate":"2026-09-24T03:22:06.1234567Z"},
			{"Name":"5319275A.WhatsAppDesktop","Version":"2.2640.100.0","InstallLocation":"","Publisher":"CN=24803D75-212C-471A-BC57-9EF86AB91435","Architecture":"Neutral","InstallDate":null}
		]`
		var got []SoftwareInfo
		if !parsePowerShellOutput([]byte(input), &got, sourceMicrosoftStore) {
			t.Fatal("parse failed")
		}
		assertKnownSource(t, got)
		calc := got[0]
		if calc.Publisher != "Microsoft Corporation" || calc.Architecture != "x64" || calc.InstallDate != "2026-09-24T03:22:06Z" {
			t.Errorf("Calculator metadata = %+v", calc)
		}
		wa := got[1]
		if wa.Publisher != "" || wa.Architecture != "noarch" || wa.InstallDate != "" {
			t.Errorf("WhatsApp metadata = %+v", wa)
		}
	})
}

func TestRegistryArch(t *testing.T) {
	cases := []struct {
		wow64  bool
		osArch string
		want   string
	}{
		{true, "AMD64", "x86"},
		{false, "AMD64", "x64"},
		{false, "x86", "x86"},
		{true, "ARM64", "x86"},
		{false, "ARM64", ""}, // native view mixes x64 and arm64 programs
		{false, "", ""},
	}
	for _, c := range cases {
		if got := registryArch(c.wow64, c.osArch); got != c.want {
			t.Errorf("registryArch(%v, %q) = %q, want %q", c.wow64, c.osArch, got, c.want)
		}
	}
}

func TestAppxPublisherName(t *testing.T) {
	cases := map[string]string{
		"CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US": "Microsoft Corporation",
		"CN=Spotify AB, O=Spotify AB, C=SE":                                                "Spotify AB",
		"CN=BS01218":                                                                       "BS01218",
		"CN=24803D75-212C-471A-BC57-9EF86AB91435":                                          "",
		"": "",
	}
	for in, want := range cases {
		if got := appxPublisherName(in); got != want {
			t.Errorf("appxPublisherName(%q) = %q, want %q", in, got, want)
		}
	}
}
