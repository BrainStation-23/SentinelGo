package epm

// ServiceOptions carries agent-wide EPM settings into the platform enforcement
// service. Its zero value is the default behavior on every platform, so
// NewService remains equivalent to NewServiceWithOptions(rules, auditor,
// ServiceOptions{}).
//
// Options that only apply to one platform are still declared here, untagged,
// so internal/main_integration.go can populate them without build tags of its
// own — the same reason Service itself has an identical exported API on every
// platform. Platforms that do not use a field ignore it.
type ServiceOptions struct {
	// WindowsTokenType selects how the Windows transport derives the token for
	// an allowed elevation. Ignored on other platforms, where the enforcement
	// daemon already runs as root and the launcher simply retains that
	// privilege. Empty means TokenElevated.
	WindowsTokenType TokenType
}
