//go:build windows

package epm

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// wtsCurrentServerHandle is the sentinel WTS_CURRENT_SERVER_HANDLE value
// (documented as (HANDLE)NULL), meaning "the local Terminal Services server".
const wtsCurrentServerHandle windows.Handle = 0

// wtsNoActiveSession is the sentinel value WTSGetActiveConsoleSessionId
// returns when no user session is attached to the physical console.
const wtsNoActiveSession = 0xFFFFFFFF

// SessionInfo describes a single Windows Terminal Services session.
type SessionInfo struct {
	SessionID uint32
	State     uint32 // one of windows.WTSActive, WTSDisconnected, etc.
}

// ActiveConsoleSessionID returns the session ID currently attached to the
// physical console (session 1 on a typical desktop, higher for RDP). Returns
// an error if no session is currently attached (e.g. at the lock/logon
// screen with fast user switching, or a headless server with nobody logged
// in).
func ActiveConsoleSessionID() (uint32, error) {
	id := windows.WTSGetActiveConsoleSessionId()
	if id == wtsNoActiveSession {
		return 0, fmt.Errorf("no active console session")
	}
	return id, nil
}

// EnumerateSessions lists every WTS session known to the local machine,
// including disconnected ones. Useful for future multi-session (RDP) support;
// the Phase 1 enforcement path only targets the active console session.
func EnumerateSessions() ([]SessionInfo, error) {
	var sessions *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(wtsCurrentServerHandle, 0, 1, &sessions, &count); err != nil {
		return nil, fmt.Errorf("WTSEnumerateSessions: %w", err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(sessions)))

	entries := unsafe.Slice(sessions, count)
	out := make([]SessionInfo, len(entries))
	for i, e := range entries {
		out[i] = SessionInfo{SessionID: e.SessionID, State: e.State}
	}
	return out, nil
}

// QueryUserToken returns the impersonation-level access token for the user
// logged into sessionID. The caller must Close() the returned token. This
// call requires SeTcbPrivilege, which the LocalSystem account holds by
// default — the agent runs as LocalSystem when installed as a Windows
// service (see docs/EPM-Capability-Assessment.md §3.1).
func QueryUserToken(sessionID uint32) (windows.Token, error) {
	var token windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &token); err != nil {
		return 0, fmt.Errorf("WTSQueryUserToken(session %d): %w", sessionID, err)
	}
	return token, nil
}

// ActiveSessionUserToken resolves the active console session and returns its
// user's impersonation-level token in one call. The caller must Close() the
// returned token.
func ActiveSessionUserToken() (token windows.Token, sessionID uint32, err error) {
	sessionID, err = ActiveConsoleSessionID()
	if err != nil {
		return 0, 0, err
	}
	token, err = QueryUserToken(sessionID)
	if err != nil {
		return 0, 0, err
	}
	return token, sessionID, nil
}

// sessionIDForProcess returns the Terminal Services session ID that pid is
// running in. Used by the IPC layer to resolve which session an elevation
// request came from, based on the OS-authenticated PID of the pipe client
// rather than any client-supplied claim.
func sessionIDForProcess(pid uint32) (uint32, error) {
	var sessionID uint32
	if err := windows.ProcessIdToSessionId(pid, &sessionID); err != nil {
		return 0, fmt.Errorf("ProcessIdToSessionId(pid %d): %w", pid, err)
	}
	return sessionID, nil
}

// userIDForToken returns a stable "DOMAIN\Username" style identity string for
// the user represented by token, used as ElevationRequest.UserID for policy
// scoping and audit records.
func userIDForToken(token windows.Token) (string, error) {
	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("GetTokenUser: %w", err)
	}

	sid := tokenUser.User.Sid

	var nameBuf, domainBuf [256]uint16
	nameLen := uint32(len(nameBuf))
	domainLen := uint32(len(domainBuf))
	var use uint32
	if err := windows.LookupAccountSid(nil, sid, &nameBuf[0], &nameLen, &domainBuf[0], &domainLen, &use); err != nil {
		// Fall back to the raw SID string; still unique and usable for policy
		// matching even if the friendly name can't be resolved.
		return sid.String(), nil
	}

	domain := windows.UTF16ToString(domainBuf[:domainLen])
	name := windows.UTF16ToString(nameBuf[:nameLen])
	if domain == "" {
		return name, nil
	}
	return domain + `\` + name, nil
}
