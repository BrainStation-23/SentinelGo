// Package flavortest skips tests of features a build doesn't have (#547).
package flavortest

import "testing"

// Require skips t when feature (a buildflavor constant) is off in this build:
// the test exercises code the read-only build leaves out.
func Require(t testing.TB, feature bool, name string) {
	t.Helper()
	if !feature {
		t.Skipf("%s is not in this build", name)
	}
}
