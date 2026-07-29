//go:build windows

package epm

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// Sentinel handles. These never reach a Windows API — the seams below
// intercept every call — so they only have to be distinguishable from each
// other and from 0.
const (
	handleFiltered windows.Token = 0x1001
	handleLinked   windows.Token = 0x1002
	handleSystem   windows.Token = 0x1003
)

// stubTokenSeams replaces the three token-derivation seams (now in
// launcher_iface_windows.go, moved there in Phase 2's transport
// de-duplication — see that file's doc comment) and records which path was
// taken, so a test can assert the *choice* rather than the syscall.
func stubTokenSeams(t *testing.T, linkedErr error) *tokenCalls {
	t.Helper()
	calls := &tokenCalls{}

	origDup, origLinked, origSystem := duplicateAsPrimaryTokenFn, linkedElevatedTokenFn, systemTokenForSessionFn
	t.Cleanup(func() {
		duplicateAsPrimaryTokenFn = origDup
		linkedElevatedTokenFn = origLinked
		systemTokenForSessionFn = origSystem
	})

	duplicateAsPrimaryTokenFn = func(windows.Token) (windows.Token, error) {
		calls.duplicate++
		return handleFiltered, nil
	}
	linkedElevatedTokenFn = func(windows.Token) (windows.Token, error) {
		calls.linked++
		if linkedErr != nil {
			return 0, linkedErr
		}
		return handleLinked, nil
	}
	systemTokenForSessionFn = func(sessionID uint32) (windows.Token, error) {
		calls.system++
		calls.systemSessionID = sessionID
		return handleSystem, nil
	}
	return calls
}

type tokenCalls struct {
	duplicate       int
	linked          int
	system          int
	systemSessionID uint32
}

// TestElevationToken_Selection is the regression test for the defect that made
// Windows EPM grant no privilege at all: the launcher used to duplicate the
// session's default (UAC-filtered) token unconditionally, so an "allowed"
// elevation produced a process with exactly the rights the requester already
// had. The default path must now reach for the linked elevated token.
func TestElevationToken_Selection(t *testing.T) {
	const sessionID = 7

	for _, tc := range []struct {
		name      string
		tokenType TokenType
		want      windows.Token
		wantCalls tokenCalls
	}{
		{
			name:      "default is elevated, not filtered",
			tokenType: "",
			want:      handleLinked,
			wantCalls: tokenCalls{linked: 1},
		},
		{
			name:      "elevated uses the linked token",
			tokenType: TokenElevated,
			want:      handleLinked,
			wantCalls: tokenCalls{linked: 1},
		},
		{
			name:      "system uses the LocalSystem token for the requester's session",
			tokenType: TokenSystem,
			want:      handleSystem,
			wantCalls: tokenCalls{system: 1, systemSessionID: sessionID},
		},
		{
			name:      "filtered restores pre-fix behavior",
			tokenType: TokenFiltered,
			want:      handleFiltered,
			wantCalls: tokenCalls{duplicate: 1},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := stubTokenSeams(t, nil)

			got, err := elevationToken(tc.tokenType, handleFiltered, sessionID)
			if err != nil {
				t.Fatalf("elevationToken: %v", err)
			}
			if got != tc.want {
				t.Errorf("token = %#x, want %#x", got, tc.want)
			}
			if *calls != tc.wantCalls {
				t.Errorf("calls = %+v, want %+v", *calls, tc.wantCalls)
			}
		})
	}
}

// TestElevationToken_StandardUserFailsLoudly pins the deliberate choice not to
// silently degrade. A true standard user has no linked elevated token, and no
// manipulation of their own token can produce one, so the request must fail
// with an actionable reason rather than launching unelevated and reporting
// success — which is exactly the failure mode being fixed.
func TestElevationToken_StandardUserFailsLoudly(t *testing.T) {
	calls := stubTokenSeams(t, ErrNoLinkedToken)

	tok, err := elevationToken(TokenElevated, handleFiltered, 3)
	if err == nil {
		_ = tok.Close()
		t.Fatal("expected an error for a requester with no linked elevated token")
	}
	if !errors.Is(err, ErrNoLinkedToken) {
		t.Errorf("error must wrap ErrNoLinkedToken, got %v", err)
	}
	if !strings.Contains(err.Error(), string(TokenSystem)) {
		t.Errorf("error should name the %q fallback so the operator knows the remedy, got %v", TokenSystem, err)
	}
	if tok != 0 {
		t.Error("no token may be returned alongside an error")
	}
	// It must NOT quietly fall back to either weaker path on its own.
	if calls.system != 0 {
		t.Error("must not silently fall back to the system token: different security semantics require an explicit opt-in")
	}
	if calls.duplicate != 0 {
		t.Error("must not silently fall back to the filtered token: that grants no privilege")
	}
}

func TestElevationToken_OtherLinkedErrorsPropagate(t *testing.T) {
	boom := errors.New("token query failed")
	stubTokenSeams(t, boom)

	if _, err := elevationToken(TokenElevated, handleFiltered, 1); !errors.Is(err, boom) {
		t.Errorf("error = %v, want it to wrap %v", err, boom)
	}
}

// TestWindowsLauncher_DefaultsInvalidTokenType covers the defaulting
// windowsLauncher.Launch itself performs (spec.Constraints.TokenType falling
// back to l.tokenType, and an invalid value on either falling back to
// TokenElevated) — the behavior NewPipeServerWithTokenType used to expose via
// a directly-inspectable field before Phase 2 wrapped it behind the Server/
// Launcher abstraction. Exercised through Launch with stubbed seams rather
// than by reaching into unexported internals.
func TestWindowsLauncher_DefaultsInvalidTokenType(t *testing.T) {
	for _, tc := range []struct {
		name           string
		launcherType   TokenType
		constraintType TokenType
		wantCalls      tokenCalls
	}{
		{"empty launcher default falls back to elevated", "", "", tokenCalls{linked: 1}},
		{"invalid launcher default falls back to elevated", "bogus", "", tokenCalls{linked: 1}},
		{"constraints override the launcher default", TokenSystem, TokenElevated, tokenCalls{linked: 1}},
		{"invalid constraints override falls back to elevated", TokenSystem, "nonsense", tokenCalls{linked: 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := stubTokenSeams(t, nil)
			origEnv, origLaunch := buildEnvironmentBlockFn, launchAsUserFn
			t.Cleanup(func() { buildEnvironmentBlockFn, launchAsUserFn = origEnv, origLaunch })
			buildEnvironmentBlockFn = func(windows.Token) (*environmentBlock, error) { return &environmentBlock{}, nil }
			launchAsUserFn = func(windows.Token, string, string, *environmentBlock) (*LaunchResult, error) {
				return &LaunchResult{ProcessID: 1}, nil
			}

			l := &windowsLauncher{tokenType: tc.launcherType}
			peer := PeerIdentity{SessionID: 7, Cred: handleFiltered}
			spec := LaunchSpec{AppPath: `C:\apps\tool.exe`, Constraints: Constraints{TokenType: tc.constraintType}}

			if _, err := l.Launch(peer, spec); err != nil {
				t.Fatalf("Launch: %v", err)
			}
			if *calls != tc.wantCalls {
				t.Errorf("calls = %+v, want %+v", *calls, tc.wantCalls)
			}
		})
	}
}

func TestWindowsLauncher_RejectsNonWindowsTokenCred(t *testing.T) {
	l := &windowsLauncher{tokenType: TokenElevated}
	_, err := l.Launch(PeerIdentity{Cred: "not-a-token"}, LaunchSpec{AppPath: `C:\apps\tool.exe`})
	if err == nil {
		t.Fatal("expected an error when PeerIdentity.Cred is not a windows.Token")
	}
}
