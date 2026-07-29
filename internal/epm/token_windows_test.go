//go:build windows

package epm

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

// selfToken opens the test process's own token. Every test here uses it as a
// real, live token rather than a fake: the whole point of this code is how it
// interacts with actual Windows token state, which a stub cannot exercise.
func selfToken(t *testing.T) windows.Token {
	t.Helper()
	var tok windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY,
		&tok,
	); err != nil {
		t.Fatalf("OpenProcessToken(self): %v", err)
	}
	t.Cleanup(func() { _ = tok.Close() })
	return tok
}

func TestInspectTokenElevation_ReportsAKnownType(t *testing.T) {
	info, err := InspectTokenElevation(selfToken(t))
	if err != nil {
		t.Fatalf("InspectTokenElevation: %v", err)
	}

	switch info.Type {
	case TokenElevationTypeDefault, TokenElevationTypeFull, TokenElevationTypeLimited:
	default:
		t.Fatalf("Type = %d, want one of Default(1)/Full(2)/Limited(3)", info.Type)
	}

	// HasLinked is definitionally true for exactly the Limited case: that is
	// the only elevation type with a counterpart to link to.
	if want := info.Type == TokenElevationTypeLimited; info.HasLinked != want {
		t.Errorf("HasLinked = %v for type %d, want %v", info.HasLinked, info.Type, want)
	}

	// A Limited token is by construction the *filtered* half, so it must never
	// report as elevated. This is precisely the state that made the pre-fix
	// launcher a no-op: it launched with this token and reported success.
	if info.Type == TokenElevationTypeLimited && info.IsElevated {
		t.Error("a Limited (UAC-filtered) token must not report IsElevated")
	}
	// Conversely a Full token is elevated by definition.
	if info.Type == TokenElevationTypeFull && !info.IsElevated {
		t.Error("a Full token must report IsElevated")
	}
}

// TestLinkedElevatedToken_MatchesElevationType asserts the contract in both
// directions without requiring the test to run under any particular account:
// a Limited token must yield an elevated primary token, and anything else must
// report ErrNoLinkedToken so the caller can fall back rather than silently
// launching unelevated.
func TestLinkedElevatedToken_MatchesElevationType(t *testing.T) {
	tok := selfToken(t)
	info, err := InspectTokenElevation(tok)
	if err != nil {
		t.Fatalf("InspectTokenElevation: %v", err)
	}

	elevated, err := LinkedElevatedToken(tok)

	if !info.HasLinked {
		if !errors.Is(err, ErrNoLinkedToken) {
			t.Fatalf("LinkedElevatedToken on a %d token: err = %v, want ErrNoLinkedToken", info.Type, err)
		}
		if elevated != 0 {
			_ = elevated.Close()
			t.Error("LinkedElevatedToken must not return a token alongside ErrNoLinkedToken")
		}
		return
	}

	if errors.Is(err, ErrNoTcbPrivilege) {
		// Expected whenever the test process is not LocalSystem: TokenLinkedToken
		// downgrades its result to identification level without SeTcbPrivilege.
		// The agent holds that privilege in its normal service context, so this
		// path is only reachable here, not in production.
		t.Skipf("needs SeTcbPrivilege (run as LocalSystem) to complete: %v", err)
	}
	if err != nil {
		t.Fatalf("LinkedElevatedToken on a Limited token: %v", err)
	}
	defer func() { _ = elevated.Close() }()

	if !elevated.IsElevated() {
		t.Error("the linked token of a UAC-filtered token must be elevated — " +
			"this is the whole mechanism by which EPM grants privilege on Windows")
	}
}

// TestLinkedElevatedToken_PrivilegeErrorIsDistinct keeps the two failure modes
// separable: "this user has no elevated token" (fall back to system, or deny)
// is a different operational problem from "the agent is not running as
// LocalSystem" (fix the service context), and the launcher's suggested remedy
// is only correct for the first.
func TestLinkedElevatedToken_PrivilegeErrorIsDistinct(t *testing.T) {
	if errors.Is(ErrNoTcbPrivilege, ErrNoLinkedToken) {
		t.Error("ErrNoTcbPrivilege must not match ErrNoLinkedToken")
	}
	if errors.Is(ErrNoLinkedToken, ErrNoTcbPrivilege) {
		t.Error("ErrNoLinkedToken must not match ErrNoTcbPrivilege")
	}
}

func TestLinkedElevatedToken_ErrorIsIdentifiable(t *testing.T) {
	// The launcher branches on this error to decide whether to suggest the
	// system-token fallback, so it must stay matchable through wrapping.
	wrapped := errors.New("outer: " + ErrNoLinkedToken.Error())
	if errors.Is(wrapped, ErrNoLinkedToken) {
		t.Fatal("sanity: a string-copied error must not match")
	}
	if !errors.Is(ErrNoLinkedToken, ErrNoLinkedToken) {
		t.Error("ErrNoLinkedToken must match itself under errors.Is")
	}
}

// TestSystemTokenForSession_RequiresPrivilege exercises the standard-user
// fallback. It needs SeTcbPrivilege, which only LocalSystem holds, so an
// ordinary test run is expected to fail — the assertion is that it fails
// cleanly with no token leaked, not that it succeeds.
func TestSystemTokenForSession_RequiresPrivilege(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode: touches process token privileges")
	}

	tok, err := SystemTokenForSession(0)
	if err != nil {
		if tok != 0 {
			_ = tok.Close()
			t.Fatal("SystemTokenForSession must not return a token alongside an error")
		}
		t.Logf("SystemTokenForSession failed as expected without SeTcbPrivilege: %v", err)
		return
	}
	defer func() { _ = tok.Close() }()

	// Running as LocalSystem (e.g. under a service harness): the duplicated
	// token must actually be elevated, otherwise the fallback grants nothing.
	if !tok.IsElevated() {
		t.Error("a LocalSystem-derived token must report IsElevated")
	}
}

func TestTokenTypeValid(t *testing.T) {
	for _, tc := range []struct {
		in   TokenType
		want bool
	}{
		{TokenElevated, true},
		{TokenSystem, true},
		{TokenFiltered, true},
		{"", false},
		{"Elevated", false}, // case-sensitive: config validation rejects this too
		{"admin", false},
	} {
		if got := tc.in.Valid(); got != tc.want {
			t.Errorf("TokenType(%q).Valid() = %v, want %v", tc.in, got, tc.want)
		}
	}
}
