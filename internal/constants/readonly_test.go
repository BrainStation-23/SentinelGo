//go:build readonly

package constants

import (
	"slices"
	"testing"
)

// The read-only build never advertises what it lacks (#547), on any OS.
func TestReadOnly_Capabilities(t *testing.T) {
	defer func(g string, p func() bool) { goos, pwshInstalled = g, p }(goos, pwshInstalled)
	pwshInstalled = func() bool { return true }
	for _, g := range []string{"windows", "darwin", "linux"} {
		goos = g
		caps := Capabilities()
		for _, c := range caps {
			if slices.Contains(ReadOnlyLacks, c) {
				t.Errorf("%s: advertises %s", g, c)
			}
		}
		for _, c := range []string{"packages_v1"} {
			if !slices.Contains(caps, c) {
				t.Errorf("%s: lost %s", g, c)
			}
		}
	}
}
