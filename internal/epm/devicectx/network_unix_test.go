//go:build linux || darwin

package devicectx

import (
	"strings"
	"testing"
)

func TestParseResolvConf(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    []string
	}{
		{"empty", "", nil},
		{
			"search line with multiple suffixes",
			"nameserver 10.0.0.1\nsearch corp.example.com eng.example.com\n",
			[]string{"corp.example.com", "eng.example.com"},
		},
		{
			"domain line",
			"domain corp.example.com\n",
			[]string{"corp.example.com"},
		},
		{
			"trailing dot and case are normalized",
			"search Corp.Example.COM.\n",
			[]string{"corp.example.com"},
		},
		{
			"comments and short lines are ignored",
			"# a comment\n; another comment\nsearch\nsearch corp.example.com\n",
			[]string{"corp.example.com"},
		},
		{
			"duplicates across search and domain are deduplicated",
			"search corp.example.com\ndomain corp.example.com\n",
			[]string{"corp.example.com"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseResolvConf(strings.NewReader(tc.content))
			if !equalStrSlices(got, tc.want) {
				t.Errorf("parseResolvConf(%q) = %v, want %v", tc.content, got, tc.want)
			}
		})
	}
}
