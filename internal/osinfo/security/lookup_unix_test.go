//go:build linux || darwin

package security

// fakeLookupBinary stands in for shared.LookupBinary in the collector tests:
// every tool "exists" under /fixed, whatever is installed on the test host.
func fakeLookupBinary(name string) (string, error) { return "/fixed/" + name, nil }
