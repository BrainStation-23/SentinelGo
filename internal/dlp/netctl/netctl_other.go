//go:build !(windows && (amd64 || arm64))

package netctl

// No per-app network filtering here: macOS would need a Network Extension,
// Linux extra kernel features (#324). The controls report
// unsupported:not_on_windows.
var platformOpen func() (Ruleset, error)

func platformEnv() map[string]string { return nil }

func platformProfiles() []string { return nil }

func platformExists(string) bool { return false }
