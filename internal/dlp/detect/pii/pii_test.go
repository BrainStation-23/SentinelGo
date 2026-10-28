package pii

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// golden pins alcatraz v0.23.0's results on our corpus. An alcatraz upgrade
// that changes any of these must be a deliberate decision, not a side effect.
var golden = []struct {
	text string
	want []string // "<detector>=<matched text>"
}{
	{"card 4111 1111 1111 1111 exp 12/29", []string{"pii.credit_card=4111 1111 1111 1111"}},
	{"card 4111111111111111", []string{"pii.credit_card=4111111111111111"}},
	{"luhn-invalid 4111111111111112", nil},
	{"amex 378282246310005", []string{"pii.credit_card=378282246310005"}},
	{"iban GB82 WEST 1234 5698 7654 32", []string{"pii.iban=GB82 WEST 1234 5698 7654 32"}},
	{"de iban DE89370400440532013000", []string{"pii.iban=DE89370400440532013000"}},
	{"bad iban GB82WEST12345698765433", nil},
	{"ssn 536-22-1234", []string{"pii.us_ssn=536-22-1234"}},
	{"ssn 000-12-3456", nil},
	{"nino AB123456C", []string{"pii.uk_nino=AB123456C"}},
	{"nino QQ123456C", nil},
	{"nhs 943 476 5919", []string{"pii.phone=943 476 5919", "pii.uk_nhs=943 476 5919"}},
	{"email jane.doe@example.com", []string{"pii.email=jane.doe@example.com"}},
	{"call +44 20 7946 0958", []string{"pii.phone=+44 20 7946 0958"}},
	// clipboard false-positive set
	{"550e8400-e29b-41d4-a716-446655440000", nil},
	{"commit 9fceb02d0ae598e95dc970b74767f19372d61af8", nil},
	{"v1.2.3 v10.20.30-rc.1 1.0.0.12345", nil},
	{"revenue grew 12.5% to $4,300,000 in Q3 2026, order #1234567890123", nil},
	{"timestamp 1730123456789 port 8080 pid 41234", nil},
	// phone is opt-in because of this:
	{"https://example.com/search?q=go&page=2&id=1234567890", []string{"pii.phone=1234567890"}},
}

func TestGolden(t *testing.T) {
	ids := []string{"pii.credit_card", "pii.iban", "pii.us_ssn", "pii.uk_nino", "pii.uk_nhs", "pii.email", "pii.phone"}
	s, unknown := New(ids)
	if len(unknown) > 0 {
		t.Fatalf("unknown ids: %v", unknown)
	}
	for _, g := range golden {
		var got []string
		for _, m := range s.Find(g.text) {
			got = append(got, fmt.Sprintf("%s=%s", m.DetectorID, g.text[m.Start:m.End]))
		}
		slices.Sort(got)
		if !slices.Equal(got, g.want) {
			t.Errorf("%q:\n got  %v\n want %v", g.text, got, g.want)
		}
	}
}

func TestNew_OnlyRequestedDetectorsRun(t *testing.T) {
	s, _ := New([]string{"pii.iban"})
	if got := s.Find("card 4111111111111111 iban DE89370400440532013000"); len(got) != 1 || got[0].DetectorID != "pii.iban" {
		t.Errorf("Find = %+v, want only the IBAN", got)
	}
}

func TestNew_UnknownIDs(t *testing.T) {
	s, unknown := New([]string{"pii.martian_id", "pii.us_bank_number", "pii.credit_card"})
	if !slices.Equal(unknown, []string{"pii.martian_id", "pii.us_bank_number"}) {
		t.Errorf("unknown = %v", unknown)
	}
	if got := s.Find("4111111111111111"); len(got) != 1 {
		t.Errorf("known detector stopped working: %+v", got)
	}
	empty, _ := New(nil)
	if got := empty.Find("4111111111111111"); got != nil {
		t.Errorf("empty scanner found %+v", got)
	}
}

func TestDetectors(t *testing.T) {
	byID := map[string]Detector{}
	for _, d := range Detectors() {
		byID[d.ID] = d
		if !strings.HasPrefix(d.ID, "pii.") {
			t.Errorf("detector id %q lacks the pii. prefix", d.ID)
		}
	}
	for _, id := range []string{"pii.credit_card", "pii.iban", "pii.us_ssn", "pii.uk_nino", "pii.uk_nhs"} {
		if d, ok := byID[id]; !ok || d.OptIn {
			t.Errorf("%s: present=%v optIn=%v, want a default detector", id, ok, d.OptIn)
		}
	}
	for _, id := range []string{"pii.email", "pii.phone"} {
		if d, ok := byID[id]; !ok || !d.OptIn {
			t.Errorf("%s: present=%v optIn=%v, want opt-in", id, ok, d.OptIn)
		}
	}
	if _, ok := byID["pii.in_pan"]; !ok {
		t.Error("country ids such as pii.in_pan should be offered (opt-in)")
	}
}
