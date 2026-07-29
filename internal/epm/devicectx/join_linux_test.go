//go:build linux

package devicectx

import "testing"

func TestParseRealmDomainName(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want string
	}{
		{"not joined", "", ""},
		{
			"joined",
			"example.com\n  type: kerberos\n  realm-name: EXAMPLE.COM\n  domain-name: example.com\n  configured: kerberos-member\n",
			"example.com",
		},
		{"no domain-name line", "example.com\n  type: kerberos\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseRealmDomainName(tc.out); got != tc.want {
				t.Errorf("parseRealmDomainName(%q) = %q, want %q", tc.out, got, tc.want)
			}
		})
	}
}
