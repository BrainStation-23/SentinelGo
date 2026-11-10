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

	"sentinelgo/internal/dlp/ipc"
	"sentinelgo/internal/dlp/policy"
)

// Supervisor starts, updates and stops the session helpers.
type Supervisor interface {
	// Apply makes sure a helper runs in every interactive session and hands
	// each one p. It is called again with every new policy. A nil p means no
	// DLP policy: helpers run with their channels stopped.
	Apply(ctx context.Context, p *policy.Compiled)
	// Stop stops every helper. Safe to call when none are running.
	Stop()
	// Sessions reports each helper's state, for the status sent to the
	// backend.
	Sessions() []Info
}

// CapNotifications is the per-session capability key for notification
// readiness (#323, contract Compliance-OS#623). It describes one user, so it
// is never rolled up to the device's channel capabilities.
const CapNotifications = "notifications"

// CapUploadRedirect is the per-session upload redirect (#426, Linux): the
// hub records each helper's answer to SetProxy ("active", "inactive" or
// "unsupported:<reason>"). Per user, like CapNotifications: the device's
// file.upload capability comes from the upload proxy service.
const CapUploadRedirect = "upload_redirect"

// PerSession reports whether a session capability describes one user only,
// so it is never rolled up to the device's capabilities.
func PerSession(capability string) bool {
	return capability == CapNotifications || capability == CapUploadRedirect
}

// Info is one session helper's state, as reported to the backend.
type Info struct {
	User      string `json:"user"`
	State     string `json:"state"`                // e.g. "running", "starting", "restarting"
	SessionID string `json:"session_id,omitempty"` // OS session (Windows) or uid (Unix)
	// Capabilities the helper reported per channel ("supported" or
	// "unsupported:<reason>"); empty for a helper that isn't connected.
	Capabilities map[string]string `json:"capabilities,omitempty"`
	// LastError is why the session's last helper connection was refused or
	// dropped before it said hello; only set while no helper is connected.
	LastError string `json:"last_error,omitempty"`
}

// Service is the session helpers as the agent runs them: always, whether DLP
// enforces or not, so an admin's notification (the notify-user task) reaches
// the signed-in user. The agent starts it with Apply(ctx, nil) and stops it
// at shutdown; DLP only sets the policy, through PolicyOnly.
type Service interface {
	Supervisor
	// Notify shows n in every session with a connected helper and returns
	// each one's answer.
	Notify(ctx context.Context, n ipc.Notify) []NotifyResult
	// OpenProfile presents p to the user of one session (its SessionID) and
	// waits for the helper's answer.
	OpenProfile(ctx context.Context, sessionID string, p ipc.OpenProfile) error
	// NotifySession shows n to the user of one session and waits for the
	// helper's answer (ErrNoHelper when none is connected).
	NotifySession(ctx context.Context, sessionID string, n ipc.Notify) error
	// AskOverride asks the user of one session what to do about a file a
	// block_override policy blocked, and waits for their answer.
	AskOverride(ctx context.Context, sessionID string, a ipc.AskOverride) (ipc.OverrideAnswer, error)
	// SessionReadiness is the notification readiness the helper of a session
	// reports (#323); ok is false when no helper is connected there.
	SessionReadiness(sessionID string) (state string, ok bool)
	// OpenURL opens an MDM enrollment link for the user of one session.
	OpenURL(ctx context.Context, sessionID string, u ipc.OpenURL) error
}

// PolicyOnly lets DLP's Manager set the policy on s without owning the
// helpers: its Stop clears the policy (helpers stay, with their channels
// stopped) instead of stopping them.
func PolicyOnly(s Supervisor) Supervisor { return policyOnly{s} }

type policyOnly struct{ s Supervisor }

func (p policyOnly) Apply(ctx context.Context, c *policy.Compiled) { p.s.Apply(ctx, c) }
func (p policyOnly) Stop()                                         { p.s.Apply(context.Background(), nil) }
func (p policyOnly) Sessions() []Info                              { return p.s.Sessions() }
