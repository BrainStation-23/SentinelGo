//go:build linux

package sessions

import (
	"context"
	"fmt"
	"os/exec"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// platformCapability reports CapSupported when loginctl is available.
// Non-systemd distributions (Alpine/OpenRC, some embedded images) lack it;
// this collector does not fall back to parsing utmp directly in this first
// cut, so those hosts are honestly reported as unsupported rather than
// guessed from an unreliable source.
func platformCapability(context.Context) tel.CapabilityState {
	if _, err := exec.LookPath("loginctl"); err != nil {
		return tel.CapUnsupported
	}
	return tel.CapSupported
}

// platformSessions lists sessions via loginctl, then queries each one's
// Remote property individually to classify it. The number of concurrent
// sessions on any real host is small (a handful at most), so one show-session
// call per session is proportionate — unlike the "one call for many items"
// rule that applies to potentially large lists like services or processes.
func platformSessions(ctx context.Context) signal {
	out, _, err := shared.RunCommandOutputContext(ctx, "loginctl", "list-sessions", "-o", "json")
	if err != nil {
		return signal{Warnings: []string{"loginctl list-sessions failed to run"}, Err: err}
	}

	list, parseErr := parseLoginctlList(out)
	if parseErr != nil {
		return signal{
			Warnings: []string{"loginctl list-sessions returned unparseable JSON"},
			Err:      fmt.Errorf("parse loginctl output: %w", tel.ErrParseFailed),
		}
	}

	var warnings []string
	sessions := make([]Session, 0, len(list))
	for _, s := range list {
		props, propErr := fetchSessionProps(ctx, s.Session)
		if propErr != nil {
			warnings = append(warnings, "loginctl show-session failed for one session; reported with defaults")
		}
		sessionType, remote := classifyLoginctlSession(s.Seat, props["Remote"])
		sessions = append(sessions, Session{
			Username:    s.User,
			SessionName: s.Session,
			SessionType: sessionType,
			Remote:      remote,
			State:       props["State"],
		})
	}

	return signal{
		Sessions: sessions,
		Source:   "exec:loginctl",
		Warnings: warnings,
	}
}

// fetchSessionProps reads a single session's Remote and State properties.
func fetchSessionProps(ctx context.Context, sessionID string) (map[string]string, error) {
	out, _, err := shared.RunCommandOutputContext(ctx, "loginctl", "show-session", sessionID, "-p", "Remote", "-p", "State")
	if err != nil {
		return nil, err
	}
	return parseKeyEqualsValue(out), nil
}
