//go:build !darwin

package mdmenroll

import "context"

// ConsoleSession: profile enrollment is macOS-only for now.
func ConsoleSession() (Session, bool) { return Session{}, false }

// RenewADE: Automated Device Enrollment is Apple's.
var RenewADE func(ctx context.Context) error

// OpenProfileForUser is nil: this platform can't present a profile.
var OpenProfileForUser func(name string, data []byte) error
