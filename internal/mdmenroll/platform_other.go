//go:build !darwin && !windows

package mdmenroll

import "context"

// ConsoleSession: the agent enrolls Macs and Windows PCs only.
func ConsoleSession() (Session, bool) { return Session{}, false }

// RenewADE: Automated Device Enrollment is Apple's.
var RenewADE func(ctx context.Context) error

// OpenProfileForUser is nil: this platform can't present a profile.
var OpenProfileForUser func(name string, data []byte) error

// OpenURLForUser is nil: enrollment links are Windows'.
var OpenURLForUser func(url string) error

// RegisterWindows and UnregisterWindows are Windows'.
var (
	RegisterWindows   func(upn, discoveryURL, accessToken string) error
	UnregisterWindows func(enrollmentID string) error
)
