// Package session runs the per-user DLP session helpers. The clipboard belongs
// to each interactive session, which the service (SYSTEM / root) can't reach,
// so the service starts one `sentinelgo dlp-session` helper per interactive
// session and pushes the compiled policy to it over IPC (internal/dlp/ipc).
//
// Each OS launches helpers its own way: WTS sessions + CreateProcessAsUser on
// Windows, a LaunchAgent in the Aqua session on macOS, a systemd user unit on
// Linux. Platforms without a launcher use session_stub.go.
package session

import (
	"context"

	"sentinelgo/internal/dlp/policy"
)

// Supervisor starts, updates and stops the session helpers.
type Supervisor interface {
	// Apply makes sure a helper runs in every interactive session and hands
	// each one p. It is called again with every new policy.
	Apply(ctx context.Context, p *policy.Compiled)
	// Stop stops every helper. Safe to call when none are running.
	Stop()
	// Sessions reports each helper's state, for the status sent to the
	// backend.
	Sessions() []Info
}

// Info is one session helper's state, as reported to the backend.
type Info struct {
	User      string `json:"user"`
	State     string `json:"state"`                // e.g. "running", "starting", "restarting"
	SessionID string `json:"session_id,omitempty"` // OS session (Windows) or uid (Unix)
	// Capabilities the helper reported per channel ("supported" or
	// "unsupported:<reason>"); empty for a helper that isn't connected.
	Capabilities map[string]string `json:"capabilities,omitempty"`
}
