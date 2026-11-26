package uninstallprotect

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

// Normalize returns the canonical form of a token as an admin typed it:
// upper case, without '-' and white space, with O→0 and I/L→1 (Crockford
// base32 reads them the same).
func Normalize(token string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(token) {
		switch r {
		case '-', ' ', '\t', '\r', '\n':
			continue
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Decision is the result of a check.
type Decision int

// Decisions. Only DecisionBlocked stops the uninstall.
const (
	// DecisionOff: protection is off, or nothing has synced.
	DecisionOff Decision = iota
	// DecisionNoHash: protection is on but no hash has synced; the contract
	// fails open.
	DecisionNoHash
	// DecisionMatch: the token matches.
	DecisionMatch
	// DecisionBlocked: protection is on and the token is missing or wrong.
	DecisionBlocked
)

// Allowed reports whether the uninstall may go on.
func (d Decision) Allowed() bool { return d != DecisionBlocked }

// String is a log line for the decision. It never contains the token.
func (d Decision) String() string {
	switch d {
	case DecisionOff:
		return "uninstall protection is off on this device"
	case DecisionNoHash:
		return "uninstall protection is on but no token has synced to this device yet; allowing the uninstall"
	case DecisionMatch:
		return "the uninstall token matches"
	default:
		return "uninstall blocked: the uninstall token is missing or wrong (the device's token is in the console, on the device's Management tab)"
	}
}

// Check decides whether token unlocks the uninstall under state (nil when
// nothing has synced). The hash compare is constant-time.
func Check(state *State, token string) Decision {
	if state == nil || !state.Enabled {
		return DecisionOff
	}
	if state.TokenHash == "" {
		return DecisionNoHash
	}
	salt, err := hex.DecodeString(state.Salt)
	if err != nil {
		return DecisionBlocked
	}
	want, err := hex.DecodeString(state.TokenHash)
	if err != nil {
		return DecisionBlocked
	}
	canonical := Normalize(token)
	if canonical == "" {
		return DecisionBlocked
	}
	h := sha256.New()
	h.Write(salt)
	h.Write([]byte(canonical))
	if subtle.ConstantTimeCompare(h.Sum(nil), want) == 1 {
		return DecisionMatch
	}
	return DecisionBlocked
}

// CheckFile is Check against the state file at path. An unreadable file
// counts as nothing synced (fail open, as the contract does before the first
// sync); the error says why, for the log.
func CheckFile(path, token string) (Decision, error) {
	s, err := Load(path)
	if err != nil {
		return DecisionOff, err
	}
	return Check(s, token), nil
}
