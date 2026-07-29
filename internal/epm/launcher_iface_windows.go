//go:build windows

package epm

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

// Seams for file hashing, publisher verification, and the actual privileged
// launch — package-level function vars, matching the identity-resolution
// seams in transport_windows.go. pipe_integration_windows_test.go stubs all
// eight; this file and transport_windows.go together are where they now
// live, unchanged in name or behavior from pre-Phase-2 pipe_windows.go.
var (
	computeFileHashFn         = ComputeFileHash
	verifyAuthenticodeFn      = VerifyAuthenticode
	duplicateAsPrimaryTokenFn = DuplicateAsPrimaryToken
	buildEnvironmentBlockFn   = BuildEnvironmentBlock
	launchAsUserFn            = LaunchAsUser
	linkedElevatedTokenFn     = LinkedElevatedToken
	systemTokenForSessionFn   = SystemTokenForSession
)

// windowsIdentifier implements Identifier for the Windows transport.
type windowsIdentifier struct{}

func (windowsIdentifier) Groups(PeerIdentity) ([]string, error) { return nil, nil }

func (windowsIdentifier) Publisher(path string) (string, error) {
	return verifyAuthenticodeFn(path)
}

// windowsLauncher implements Launcher for the Windows transport: it derives
// the elevation token per Constraints/tokenType (see elevationToken, the
// Phase 0 fix for the filtered-token bug) and performs the actual
// CreateProcessAsUser launch via launchAsUserFn.
type windowsLauncher struct {
	// tokenType is the agent-wide default (from ServiceOptions), used
	// whenever a matched rule's Constraints does not specify its own
	// TokenType (Constraints.EffectiveTokenType's zero value maps to
	// TokenElevated, not to this field — see Launch).
	tokenType TokenType
}

// Launch performs the privileged launch. Callers (Server.elevate) must only
// reach this after policy has already allowed the request.
func (l *windowsLauncher) Launch(peer PeerIdentity, spec LaunchSpec) (*Launched, error) {
	userToken, ok := peer.Cred.(windows.Token)
	if !ok {
		return nil, fmt.Errorf("epm: peer identity carries no Windows token")
	}

	tokenType := spec.Constraints.TokenType
	if tokenType == "" {
		tokenType = l.tokenType
	}
	if !tokenType.Valid() {
		tokenType = TokenElevated
	}

	primary, err := elevationToken(tokenType, userToken, peer.SessionID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = primary.Close() }()

	env, err := buildEnvironmentBlockFn(primary)
	if err != nil {
		return nil, err
	}
	defer func() { _ = env.Close() }()

	// spec.AppPath is always the interpreter/executable to launch. When a
	// script is requested, the process's own command line must be
	// "interpreter <scriptPath> [args]", not just "interpreter [args]" — so
	// the quoted script path (plus its args) replaces CommandLine entirely,
	// exactly as pre-Phase-2 pipe_windows.go's launch did.
	commandLine := spec.CommandLine
	if spec.ScriptPath != "" {
		commandLine = quoteWindowsArg(spec.ScriptPath)
		if spec.ScriptArgs != "" {
			commandLine += " " + spec.ScriptArgs
		}
	}

	result, err := launchAsUserFn(primary, spec.AppPath, commandLine, env)
	if err != nil {
		return nil, err
	}
	return &Launched{ProcessID: result.ProcessID}, nil
}

// elevationToken derives the token an allowed launch should actually run
// with. See token_windows.go's InspectTokenElevation/LinkedElevatedToken/
// SystemTokenForSession doc comments for the underlying mechanics and why
// TokenElevated (not the session's default/filtered token) is the correct
// default — this is the Phase 0 fix for the bug that made Windows EPM grant
// no privilege at all.
func elevationToken(tokenType TokenType, userToken windows.Token, sessionID uint32) (windows.Token, error) {
	switch tokenType {
	case TokenFiltered:
		// Escape hatch: reproduce the pre-fix behavior exactly.
		return duplicateAsPrimaryTokenFn(userToken)

	case TokenSystem:
		return systemTokenForSessionFn(sessionID)

	default: // TokenElevated
		primary, err := linkedElevatedTokenFn(userToken)
		if err == nil {
			return primary, nil
		}
		if !errors.Is(err, ErrNoLinkedToken) {
			return 0, err
		}
		// A true standard user has no elevated token to link to, and no
		// adjustment of their own token can create one. Fail with a precise
		// reason rather than silently launching unelevated.
		return 0, fmt.Errorf("%w; set epm_windows_token_type=%q to launch as LocalSystem in the user's session instead",
			err, TokenSystem)
	}
}
