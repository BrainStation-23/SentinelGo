//go:build windows

package devicectx

import "testing"

func TestMergeDNSSuffixLists(t *testing.T) {
	cases := []struct {
		name               string
		searchList, domain string
		want               []string
	}{
		{"both empty", "", "", nil},
		{"search list only", "corp.example.com,eng.example.com", "", []string{"corp.example.com", "eng.example.com"}},
		{"domain only", "", "corp.example.com", []string{"corp.example.com"}},
		{"trailing dot and case normalized", "Corp.Example.COM.", "", []string{"corp.example.com"}},
		{"duplicates across search and domain deduplicated", "corp.example.com", "corp.example.com", []string{"corp.example.com"}},
		{"search list preserves order, domain appended", "b.example.com,a.example.com", "c.example.com", []string{"b.example.com", "a.example.com", "c.example.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeDNSSuffixLists(tc.searchList, tc.domain)
			if !equalStrSlices(got, tc.want) {
				t.Errorf("mergeDNSSuffixLists(%q, %q) = %v, want %v", tc.searchList, tc.domain, got, tc.want)
			}
		})
	}
}
