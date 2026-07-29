//go:build darwin

package devicectx

import "testing"

func TestParseDsconfigadDomain(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want string
	}{
		{"not bound", "", ""},
		{
			"bound",
			"Active Directory Forest    = example.com\nActive Directory Domain    = example.com\nComputer Account            = MYMAC\n",
			"example.com",
		},
		{"no matching line", "Computer Account = MYMAC\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseDsconfigadDomain(tc.out); got != tc.want {
				t.Errorf("parseDsconfigadDomain(%q) = %q, want %q", tc.out, got, tc.want)
			}
		})
	}
}
