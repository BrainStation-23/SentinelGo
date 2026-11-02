//go:build !windows

package mdmenroll

import "context"

// startSession: macOS's MDM client is woken by APNs, which the MDM server
// sends; the agent has nothing to start.
var startSession func(ctx context.Context, enrollmentID string) error
