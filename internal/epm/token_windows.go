//go:build windows

package epm

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrNoLinkedToken reports that a token has no linked elevated counterpart:
// the requester is a true standard user, not an administrator running under
// UAC. There is no token of theirs that can be elevated — see
// LinkedElevatedToken.
var ErrNoLinkedToken = errors.New("epm: token has no linked elevated token (requester is a standard user)")

// ErrNoTcbPrivilege reports that the linked elevated token could be located but
// not used, because the process lacks SeTcbPrivilege.
//
// TokenLinkedToken downgrades its result to an *identification*-level token for
// callers without SeTcbPrivilege, and an identification-level token cannot be
// duplicated up to the impersonation level CreateProcessAsUser needs. The agent
// holds SeTcbPrivilege when it runs as LocalSystem (its normal service
// context), so encountering this in production means the agent is running as
// something else — typically a foreground `-run` session started from an admin
// shell rather than as the installed service.
var ErrNoTcbPrivilege = errors.New("epm: cannot use linked elevated token without SeTcbPrivilege (agent must run as LocalSystem)")

// TOKEN_ELEVATION_TYPE values. golang.org/x/sys/windows exposes the
// TokenElevationType information class but not the enum it returns, so the
// three values from winnt.h are declared here.
const (
	// TokenElevationTypeDefault means the token is not split: either UAC is
	// off, or the requester is a true standard user. There is no linked token.
	TokenElevationTypeDefault uint32 = 1
	// TokenElevationTypeFull means this token is the elevated half of a split
	// token (or an unsplit token that already has admin rights).
	TokenElevationTypeFull uint32 = 2
	// TokenElevationTypeLimited means this is the filtered half of an
	// administrator's split token; the elevated half is reachable via
	// TokenLinkedToken.
	TokenElevationTypeLimited uint32 = 3
)

// TokenElevationInfo describes where a token sits in UAC's split-token model,
// so the launcher can choose an elevation mechanism instead of silently
// launching with whatever it was handed.
type TokenElevationInfo struct {
	// Type is one of TokenElevationTypeDefault, TokenElevationTypeFull, or
	// TokenElevationTypeLimited.
	Type uint32
	// IsElevated reports whether the token currently carries elevated rights.
	IsElevated bool
	// HasLinked reports whether a linked token exists to swap to. Only a
	// Limited token has one.
	HasLinked bool
}

// InspectTokenElevation reports the split-token state of t.
//
// This matters because WTSQueryUserToken hands back the session's *default*
// token, which for an administrator under UAC is the filtered half — the one
// with Administrators marked deny-only. Launching with it grants no privilege
// at all, so the caller has to know which case it is in before deciding what
// to launch with.
func InspectTokenElevation(t windows.Token) (TokenElevationInfo, error) {
	var info TokenElevationInfo

	var elevationType uint32
	var returned uint32
	if err := windows.GetTokenInformation(
		t,
		windows.TokenElevationType,
		(*byte)(unsafe.Pointer(&elevationType)),
		uint32(unsafe.Sizeof(elevationType)),
		&returned,
	); err != nil {
		return info, fmt.Errorf("GetTokenInformation(TokenElevationType): %w", err)
	}
	info.Type = elevationType
	info.HasLinked = elevationType == TokenElevationTypeLimited
	info.IsElevated = t.IsElevated()
	return info, nil
}

// LinkedElevatedToken returns the full-administrator token linked to a
// UAC-filtered token, duplicated to primary so CreateProcessAsUser can use it.
// The caller must Close() the result.
//
// This is the mechanism that actually grants privilege on Windows. UAC splits
// an administrator's logon into two tokens: a filtered one (used for the
// interactive session, with the Administrators SID marked
// SE_GROUP_USE_FOR_DENY_ONLY) and a full one reachable only through
// TokenLinkedToken. WTSQueryUserToken returns the filtered half, so an
// elevation that does not make this call launches the target with exactly the
// privileges the requester already had.
//
// Returns ErrNoLinkedToken when filtered is not a Limited token — a true
// standard user has no elevated counterpart to link to. That case cannot be
// rescued by adjusting the token: deny-only SIDs cannot be re-enabled with
// AdjustTokenGroups (that is the documented point of the flag), and forging a
// token with NtCreateToken requires SeCreateTokenPrivilege, which LocalSystem
// does not hold. The caller must fall back to SystemTokenForSession or deny.
func LinkedElevatedToken(filtered windows.Token) (windows.Token, error) {
	info, err := InspectTokenElevation(filtered)
	if err != nil {
		return 0, err
	}
	if !info.HasLinked {
		return 0, ErrNoLinkedToken
	}

	// TokenLinkedToken yields an impersonation-level handle; CreateProcessAsUser
	// requires a primary token, hence the duplication below.
	linked, err := filtered.GetLinkedToken()
	if err != nil {
		return 0, fmt.Errorf("GetLinkedToken: %w", err)
	}
	defer func() { _ = linked.Close() }()

	// MAXIMUM_ALLOWED rather than TOKEN_ALL_ACCESS: the handle TokenLinkedToken
	// hands back carries only the access rights the caller was granted, which
	// is generally less than TOKEN_ALL_ACCESS. Asking for more than the source
	// handle holds fails with a misleading "invalid impersonation level" error
	// rather than an access-denied. MAXIMUM_ALLOWED asks for whatever is
	// actually available, which is the conventional form for this call and is
	// sufficient for CreateProcessAsUser.
	var primary windows.Token
	if err := windows.DuplicateTokenEx(
		linked,
		windows.MAXIMUM_ALLOWED,
		nil, // default security attributes
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&primary,
	); err != nil {
		if errors.Is(err, windows.ERROR_BAD_IMPERSONATION_LEVEL) {
			// TokenLinkedToken silently returned an identification-level token
			// because we lack SeTcbPrivilege. Report that cause rather than the
			// raw errno, which names the symptom and sends operators looking in
			// the wrong place.
			return 0, ErrNoTcbPrivilege
		}
		return 0, fmt.Errorf("duplicate linked token to primary: %w", err)
	}
	return primary, nil
}

// SystemTokenForSession duplicates the agent's own LocalSystem token and
// retargets it at sessionID, so CreateProcessAsUser can render the launched
// process on that session's desktop. The caller must Close() the result.
//
// This is the fallback for a true standard user, who has no linked elevated
// token. The security semantics genuinely differ from LinkedElevatedToken and
// callers must surface that: the process runs as SYSTEM, not as the user, so
// it has no HKCU hive, no user profile, and no user network identity. It is
// also strictly more privileged than an administrator's elevated token.
//
// Requires SeTcbPrivilege (to set the session ID) and
// SeAssignPrimaryTokenPrivilege, both held by LocalSystem by default.
func SystemTokenForSession(sessionID uint32) (windows.Token, error) {
	var self windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY,
		&self,
	); err != nil {
		return 0, fmt.Errorf("OpenProcessToken(self): %w", err)
	}
	defer func() { _ = self.Close() }()

	primary, err := DuplicateAsPrimaryToken(self)
	if err != nil {
		return 0, fmt.Errorf("duplicate LocalSystem token: %w", err)
	}

	if err := windows.SetTokenInformation(
		primary,
		windows.TokenSessionId,
		(*byte)(unsafe.Pointer(&sessionID)),
		uint32(unsafe.Sizeof(sessionID)),
	); err != nil {
		_ = primary.Close()
		return 0, fmt.Errorf("SetTokenInformation(TokenSessionId=%d): %w", sessionID, err)
	}
	return primary, nil
}

// DuplicateAsPrimaryToken duplicates srcToken (typically the impersonation-
// level token returned by WTSQueryUserToken) into a new primary token
// suitable for CreateProcessAsUser. The caller must Close() the returned
// token.
func DuplicateAsPrimaryToken(srcToken windows.Token) (windows.Token, error) {
	var dup windows.Token
	err := windows.DuplicateTokenEx(
		srcToken,
		windows.TOKEN_ALL_ACCESS,
		nil, // default security attributes
		windows.SecurityImpersonation,
		windows.TokenPrimary,
		&dup,
	)
	if err != nil {
		return 0, fmt.Errorf("DuplicateTokenEx: %w", err)
	}
	return dup, nil
}

// environmentBlock wraps the *uint16 CreateEnvironmentBlock/DestroyEnvironmentBlock
// pair so callers cannot forget to free it.
type environmentBlock struct {
	ptr *uint16
}

// BuildEnvironmentBlock creates the user environment block (HKCU-derived
// variables, per-user paths, etc.) for token, as required by
// CreateProcessAsUser. The caller must call Close() on the result.
func BuildEnvironmentBlock(token windows.Token) (*environmentBlock, error) {
	var block *uint16
	if err := windows.CreateEnvironmentBlock(&block, token, false); err != nil {
		return nil, fmt.Errorf("CreateEnvironmentBlock: %w", err)
	}
	return &environmentBlock{ptr: block}, nil
}

// Close releases the environment block. Safe to call on a zero-value/already
// freed block.
func (b *environmentBlock) Close() error {
	if b == nil || b.ptr == nil {
		return nil
	}
	err := windows.DestroyEnvironmentBlock(b.ptr)
	b.ptr = nil
	if err != nil {
		return fmt.Errorf("DestroyEnvironmentBlock: %w", err)
	}
	return nil
}
