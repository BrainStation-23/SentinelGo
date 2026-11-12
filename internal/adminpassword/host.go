package adminpassword

import (
	"errors"
	"time"
)

// AccountInfo is the target account as the OS reports it. It never holds a
// password.
type AccountInfo struct {
	Name    string
	SID     string
	Builtin bool // RID 500
	Enabled bool
	// PasswordLastSet is when the password last changed (second
	// granularity on Windows).
	PasswordLastSet time.Time
	// LastLogon is the account's last logon on this device; zero if never.
	LastLogon time.Time
}

// Host errors.
var (
	// ErrAccountNotFound: the policy's account doesn't exist on the device.
	ErrAccountNotFound = errors.New("account not found")
	// ErrPasswordPolicy: the device's password rules rejected the password.
	ErrPasswordPolicy = errors.New("the device's password policy rejected the new password")
)

// Host is the device side: the platform's account and LAPS state. The
// Windows implementation uses netapi32 and the registry, never a command
// line, so the password is never on one.
type Host interface {
	// Unsupported returns why this device can't rotate (a domain
	// controller, another OS), or "".
	Unsupported() string
	// ManagedBy returns ManagedByWindowsLAPS or ManagedByLegacyLAPS when
	// another rotator owns the password, or "".
	ManagedBy() (string, error)
	// Account resolves the policy's account: "" is the built-in
	// Administrator (RID 500, by SID), otherwise a local account name.
	Account(name string) (AccountInfo, error)
	// AccountBySID looks up an account by SID (to settle a pending rotation
	// whose target has since changed).
	AccountBySID(sid string) (AccountInfo, error)
	// SetPassword sets the account's password. It must not keep pw.
	SetPassword(a AccountInfo, pw []byte) error
}
