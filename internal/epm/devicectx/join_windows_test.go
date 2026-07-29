//go:build windows

package devicectx

import (
	"testing"

	"sentinelgo/internal/epm"
)

const sampleDsregcmdOutput = `
+----------------------------------------------------------------------+
| Device State                                                         |
+----------------------------------------------------------------------+

             AzureAdJoined : YES
          EnterpriseJoined : NO
              DomainJoined : YES
               Device Name : DESKTOP-ABC123

+----------------------------------------------------------------------+
| Tenant Details                                                       |
+----------------------------------------------------------------------+

                TenantName : Contoso
                  TenantId : 11111111-2222-3333-4444-555555555555
`

func TestParseDsregcmdFields(t *testing.T) {
	fields := parseDsregcmdFields(sampleDsregcmdOutput)
	cases := map[string]string{
		"azureadjoined": "YES",
		"domainjoined":  "YES",
		"tenantid":      "11111111-2222-3333-4444-555555555555",
	}
	for key, want := range cases {
		if got := fields[key]; got != want {
			t.Errorf("fields[%q] = %q, want %q", key, got, want)
		}
	}
}

func TestParseDsregcmdFields_Empty(t *testing.T) {
	fields := parseDsregcmdFields("")
	if len(fields) != 0 {
		t.Errorf("parseDsregcmdFields(\"\") = %v, want empty map", fields)
	}
}

func TestTriFromYesNo(t *testing.T) {
	cases := map[string]epm.Tri{
		"YES":     epm.TriTrue,
		"yes":     epm.TriTrue,
		"NO":      epm.TriFalse,
		"no":      epm.TriFalse,
		"":        epm.TriUnknown,
		"garbage": epm.TriUnknown,
	}
	for in, want := range cases {
		if got := triFromYesNo(in); got != want {
			t.Errorf("triFromYesNo(%q) = %v, want %v", in, got, want)
		}
	}
}
