//go:build windows

package software

import (
	"os/exec"
	"strings"
	"testing"

	"sentinelgo/internal/binpath"
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
		`CN="Acme, Inc.", O="Acme, Inc.", C=US`:                                            "Acme, Inc.",
		`CN=Acme\, Inc., C=US`:                                                             "Acme, Inc.",
		`O="Say ""Hi"", Ltd.", C=US`:                                                       `Say "Hi", Ltd.`,
		`CN=Fallback; C=US`:                                                                "Fallback",
		`O="Unbalanced, C=US`:                                                              "Unbalanced, C=US",
		"":                                                                                 "",
	}
	for in, want := range cases {
		if got := appxPublisherName(in); got != want {
			t.Errorf("appxPublisherName(%q) = %q, want %q", in, got, want)
		}
	}
}

// An x86 and an x64 install of one program must both reach the catalog, while
// the same program listed under several hives is reported once.
func TestParsePowerShellOutputMultiArch(t *testing.T) {
	orig := windowsOSArch
	windowsOSArch = func() string { return "AMD64" }
	t.Cleanup(func() { windowsOSArch = orig })

	t.Run("registry", func(t *testing.T) {
		input := `[
			{"Name":"ExampleTool","Version":"2.0","Wow64":false},
			{"Name":"ExampleTool","Version":"1.0","Wow64":true},
			{"Name":"Chrome","Version":"130","Wow64":false},
			{"Name":"chrome","Version":"130","Wow64":false}
		]`
		var got []SoftwareInfo
		if !parsePowerShellOutput([]byte(input), &got, sourcePrograms) {
			t.Fatal("parse failed")
		}
		want := map[string]string{"ExampleTool:x64": "2.0", "ExampleTool:x86": "1.0", "Chrome": "130"}
		if len(got) != len(want) {
			t.Fatalf("got %d items %+v, want %d", len(got), got, len(want))
		}
		for _, sw := range got {
			if v, ok := want[sw.Name]; !ok || v != sw.InstalledVersion {
				t.Errorf("unexpected item %q version %q", sw.Name, sw.InstalledVersion)
			}
		}
	})

	t.Run("appx", func(t *testing.T) {
		input := `[
			{"Name":"Microsoft.VCLibs","Version":"14.0","Architecture":"X64"},
			{"Name":"Microsoft.VCLibs","Version":"14.0","Architecture":"X86"},
			{"Name":"Microsoft.Paint","Version":"11.0","Architecture":"X64"},
			{"Name":"Microsoft.Paint","Version":"11.0","Architecture":"X64"}
		]`
		var got []SoftwareInfo
		if !parsePowerShellOutput([]byte(input), &got, sourceMicrosoftStore) {
			t.Fatal("parse failed")
		}
		names := make([]string, len(got))
		for i, sw := range got {
			names[i] = sw.Name
		}
		if strings.Join(names, ",") != "Microsoft.VCLibs:x64,Microsoft.VCLibs:x86,Microsoft.Paint" {
			t.Errorf("names = %v", names)
		}
	})
}

// TestParsePowerShellOutputIdentifiers covers the identifiers added for
// catalog matching (#562) on a recorded registry and Appx query result.
func TestParsePowerShellOutputIdentifiers(t *testing.T) {
	orig := windowsOSArch
	windowsOSArch = func() string { return "AMD64" }
	t.Cleanup(func() { windowsOSArch = orig })

	// Sorted by Name, ArpKey as the registry query emits it.
	registry := `[
		{"Name":"7-Zip 23.01 (x64)","Version":"23.01","InstallLocation":"","InstallDate":null,"Publisher":"Igor Pavlov","EstimatedSize":5771,"Wow64":false,
		 "ArpKey":"7-Zip","SystemComponent":0,"ParentKeyName":null,"ReleaseType":null,"Homepage":" https://www.7-zip.org/ "},
		{"Name":"Google Chrome","Version":"131.0.6778.86","InstallLocation":"","InstallDate":"20261120","Publisher":"Google LLC","EstimatedSize":null,"Wow64":false,
		 "ArpKey":"{8A69D345-D564-463c-AFF1-A69D9E530F96}","SystemComponent":0,"ParentKeyName":null,"ReleaseType":null,"Homepage":null},
		{"Name":"Google Chrome","Version":"130.0.0.0","InstallLocation":"","InstallDate":"","Publisher":"Google LLC","EstimatedSize":null,"Wow64":false,
		 "ArpKey":"Google Chrome","SystemComponent":0,"ParentKeyName":null,"ReleaseType":null,"Homepage":null},
		{"Name":"Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.38.33130","Version":"14.38.33130","InstallLocation":"","InstallDate":"20261001","Publisher":"Microsoft Corporation","EstimatedSize":2312,"Wow64":false,
		 "ArpKey":"{A181A302-3F6D-4BAD-97A8-A426A6499D78}","SystemComponent":1,"ParentKeyName":null,"ReleaseType":null,"Homepage":null},
		{"Name":"Security Update for Contoso Office (KB5002651)","Version":"","InstallLocation":"","InstallDate":"","Publisher":"Contoso","EstimatedSize":null,"Wow64":true,
		 "ArpKey":"{90160000-0011-0000-0000-0000000FF1CE}_Office16.PROPLUS_{6E5A7F8B}","SystemComponent":0,"ParentKeyName":"Office16.PROPLUS","ReleaseType":" Update ","Homepage":"javascript:alert(document.cookie)"}
	]`
	var got []SoftwareInfo
	if !parsePowerShellOutput([]byte(registry), &got, sourcePrograms) {
		t.Fatal("parse registry failed")
	}
	type ids struct {
		ProductCode, ParentKeyName, ReleaseType, HomepageURL string
		SystemComponent                                      bool
	}
	want := []struct {
		name string
		ids  ids
	}{
		{"7-Zip 23.01 (x64)", ids{ProductCode: "7-Zip", HomepageURL: "https://www.7-zip.org/"}},
		// A duplicate name keeps the first row in sort order, so its
		// ProductCode is stable between runs.
		{"Google Chrome", ids{ProductCode: "{8A69D345-D564-463c-AFF1-A69D9E530F96}"}},
		{"Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.38.33130", ids{ProductCode: "{A181A302-3F6D-4BAD-97A8-A426A6499D78}", SystemComponent: true}},
		{"Security Update for Contoso Office (KB5002651)", ids{
			ProductCode:   "{90160000-0011-0000-0000-0000000FF1CE}_Office16.PROPLUS_{6E5A7F8B}",
			ParentKeyName: "Office16.PROPLUS", ReleaseType: "Update",
		}},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d programs, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		gotIDs := ids{g.ProductCode, g.ParentKeyName, g.ReleaseType, g.HomepageURL, g.SystemComponent}
		if g.Name != w.name || gotIDs != w.ids {
			t.Errorf("[%d] %q %+v, want %q %+v", i, g.Name, gotIDs, w.name, w.ids)
		}
		if g.PackageFamilyName != "" {
			t.Errorf("[%d] PackageFamilyName = %q on a registry program", i, g.PackageFamilyName)
		}
	}
	if got[1].InstalledVersion != "131.0.6778.86" {
		t.Errorf("Chrome kept version %q, want the first row's", got[1].InstalledVersion)
	}

	store := `[
		{"Name":"Microsoft.WindowsTerminal","Version":"1.21.3231.0","InstallLocation":"","Publisher":"CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US","Architecture":"X64","PackageFamilyName":"Microsoft.WindowsTerminal_8wekyb3d8bbwe","InstallDate":null,"ArpKey":"ignored"},
		{"Name":"Legacy.App","Version":"1.0.0.0","InstallLocation":"","Publisher":"CN=Legacy","Architecture":"Neutral","InstallDate":null}
	]`
	got = nil
	if !parsePowerShellOutput([]byte(store), &got, sourceMicrosoftStore) {
		t.Fatal("parse store failed")
	}
	if len(got) != 2 {
		t.Fatalf("got %d store apps, want 2", len(got))
	}
	if got[0].PackageFamilyName != "Microsoft.WindowsTerminal_8wekyb3d8bbwe" || got[0].ProductCode != "" {
		t.Errorf("Terminal = %+v", got[0])
	}
	if got[1].PackageFamilyName != "" {
		t.Errorf("Legacy.App PackageFamilyName = %q, want empty", got[1].PackageFamilyName)
	}
}

// Windows PowerShell writes redirected output in the console's legacy code
// page unless told otherwise; psUTF8 makes a non-ASCII uninstall key arrive
// intact. The script builds the name from [char] codes so the command line
// itself stays ASCII, as the real queries are.
func TestPowerShellOutputIsUTF8(t *testing.T) {
	ps := binpath.Resolve("powershell")
	if _, err := exec.LookPath(ps); err != nil {
		t.Skipf("powershell not available: %v", err)
	}
	script := psUTF8 + `@(@{Name=('Caf' + [char]0xE9 + ' Tools'); ArpKey=('Caf' + [char]0xE9 + ' Tools_is1'); Version='1.0'}) | ConvertTo-Json`
	out, err := exec.Command(ps, "-NoProfile", "-Command", script).Output()
	if err != nil {
		t.Fatalf("powershell: %v", err)
	}
	var got []SoftwareInfo
	if !parsePowerShellOutput(out, &got, sourcePrograms) || len(got) != 1 {
		t.Fatalf("parse %q: %+v", out, got)
	}
	if got[0].Name != "Café Tools" || got[0].ProductCode != "Café Tools_is1" {
		t.Errorf("Name %q ProductCode %q, want the é intact (output %q)", got[0].Name, got[0].ProductCode, out)
	}
}

func TestParsePowerShellOutput_BOM(t *testing.T) {
	var got []SoftwareInfo
	if !parsePowerShellOutput([]byte("\xEF\xBB\xBF[{\"Name\":\"Git\"}]"), &got, sourcePrograms) || len(got) != 1 {
		t.Fatalf("output with a BOM: %+v", got)
	}
}
