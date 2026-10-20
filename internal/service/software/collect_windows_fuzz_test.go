//go:build windows

package software

// Fuzz targets for the Windows software metadata parsers. Uninstall keys and
// Appx manifests are written by the installer or package author, so the
// PowerShell output is untrusted input: parsing must never panic and every
// entry must carry a known source.
//
// The seed corpus runs as an ordinary unit test under `go test ./...`.
// To actually fuzz one target:
//
//	go test -run='^$' -fuzz='^FuzzParsePowerShellOutput$' -fuzztime=1m ./internal/service/software/

import (
	"strings"
	"testing"
)

func FuzzParsePowerShellOutput(f *testing.F) {
	f.Add(`[{"Name":"7-Zip","Version":"26.01","InstallDate":"20260801","Publisher":"Igor Pavlov <x@y>","EstimatedSize":5771,"Wow64":false}]`, false)
	f.Add(`{"Name":"Calc","Publisher":"CN=Microsoft Corporation, O=Microsoft Corporation","Architecture":"X64","InstallDate":"2026-09-24T03:22:06.1234567Z"}`, true)
	f.Add(`[{"Name":"x","EstimatedSize":-5,"InstallDate":99,"Wow64":"yes","Architecture":7}]`, false)
	f.Add(`[{"Name":"x","EstimatedSize":1e300}]`, false)
	f.Add(`[{"Name":"Tool","Wow64":false},{"Name":"Tool","Wow64":true},{"Name":"tool","Wow64":true}]`, false)
	f.Add(`[{"Name":"Lib","Architecture":"X64"},{"Name":"Lib","Architecture":"X86"}]`, true)
	f.Add(`not json`, false)
	f.Add(``, true)
	f.Fuzz(func(t *testing.T, s string, store bool) {
		source := sourcePrograms
		if store {
			source = sourceMicrosoftStore
		}
		var got []SoftwareInfo
		parsePowerShellOutput([]byte(s), &got, source)
		assertKnownSource(t, got)
		for _, sw := range got {
			if sw.InstallDate != "" && !strings.HasSuffix(sw.InstallDate, "Z") {
				t.Errorf("%q: install date %q is not UTC RFC 3339", sw.Name, sw.InstallDate)
			}
		}
	})
}

func FuzzAppxPublisherName(f *testing.F) {
	f.Add("CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US")
	f.Add("CN=24803D75-212C-471A-BC57-9EF86AB91435")
	f.Add(`CN="Quoted, Inc.", O="Quoted, Inc."`)
	f.Add(`CN=Escaped\, Inc.; O="Say ""Hi"""`)
	f.Add(`O="unterminated, C=US`)
	f.Add(`O=trailing\`)
	f.Add("O=, CN=")
	f.Add("=,=,,")
	f.Add("")
	f.Fuzz(func(t *testing.T, dn string) {
		got := appxPublisherName(dn)
		if guidCN.MatchString(got) {
			t.Errorf("appxPublisherName(%q) = %q is a bare GUID", dn, got)
		}
		if got != strings.TrimSpace(got) {
			t.Errorf("appxPublisherName(%q) = %q has surrounding space", dn, got)
		}
	})
}
