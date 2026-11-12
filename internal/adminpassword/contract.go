// Package adminpassword rotates a local administrator account's password on
// a schedule and after each use, and escrows every new password to the
// backend's vault before it changes anything on the device (#361). Windows
// LAPS can't do this for a third-party MDM: its BackupDirectory only targets
// Entra ID or Active Directory.
//
// The contract is docs/admin-password-rotation.md (backend:
// Compliance-OS#892). The password is never logged, never written to disk
// and never put in a status, task note or error.
package adminpassword

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// RPC names (contract §1–3).
const (
	RPCGetPolicy = "agent_get_admin_password_policy"
	RPCEscrow    = "agent_escrow_admin_password"
	RPCConfirm   = "agent_confirm_admin_password"
)

// TaskRotate is the native task that polls now and rotates if due (§4).
const TaskRotate = "admin-password-rotate"

// SQL states the RPCs raise.
const (
	// SQLStateInvalid is a rejected parameter (malformed status or payload).
	SQLStateInvalid = "22023"
	// SQLStateNotFound is an unknown rotation id on confirm.
	SQLStateNotFound = "P0002"
)

// Policy limits and defaults (§1).
const (
	MinLength            = 14
	MaxLength            = 64
	DefaultLength        = 24
	DefaultComplexity    = 4
	DefaultRotateDays    = 30
	MaxRotateDays        = 365
	DefaultPostUseHours  = 8
	MaxPostUseHours      = 168
	maxAccountNameLength = 20
	// MaxStatusBytes is the server's limit on p_status.
	MaxStatusBytes = 8 << 10
	// maxResponseBytes bounds the policy response the agent decodes.
	maxResponseBytes = 64 << 10
)

// States reported in Status.State.
const (
	StateActive           = "active"
	StateDisabled         = "disabled"
	StateManagedElsewhere = "managed_elsewhere"
	StateUnsupported      = "unsupported"
	StateError            = "error"
)

// Values of Status.ManagedBy.
const (
	ManagedByWindowsLAPS = "windows_laps"
	ManagedByLegacyLAPS  = "legacy_laps"
)

// Rotation reasons (§2).
const (
	ReasonInitial        = "initial"
	ReasonScheduled      = "scheduled"
	ReasonPostUse        = "post_use"
	ReasonRequested      = "requested"
	ReasonAccountChanged = "account_changed"
)

// Error codes in Status.LastError and confirm payloads (§1). None of them
// carries a password.
const (
	ErrCodeAccountNotFound = "account_not_found"
	ErrCodeAccountLookup   = "account_lookup_failed"
	ErrCodePasswordPolicy  = "password_policy"
	ErrCodeSetFailed       = "set_failed"
	ErrCodeEscrowFailed    = "escrow_failed"
	ErrCodeConfirmFailed   = "confirm_failed"
	ErrCodeNotApplied      = "not_applied"
)

// Confirm states (§3).
const (
	ConfirmApplied = "applied"
	ConfirmFailed  = "failed"
)

// Account names the policy's target. Name "" means the built-in
// Administrator (RID 500), found by SID so a renamed one is still found.
type Account struct {
	Name string `json:"name"`
}

// PasswordRules are the generated password's length and character classes.
type PasswordRules struct {
	Length int `json:"length"`
	// Complexity is Windows LAPS' scale: 1 upper case, 2 + lower case,
	// 3 + digits, 4 + symbols.
	Complexity int `json:"complexity"`
}

// Policy is the resolved policy for this device.
type Policy struct {
	Version           string        `json:"version"`
	Enabled           bool          `json:"enabled"`
	Account           Account       `json:"account"`
	Password          PasswordRules `json:"password"`
	RotateEveryDays   int           `json:"rotate_every_days"`
	PostUseDelayHours *int          `json:"post_use_delay_hours"`
}

// RotateEvery is the scheduled rotation interval.
func (p Policy) RotateEvery() time.Duration {
	return time.Duration(p.RotateEveryDays) * 24 * time.Hour
}

// PostUseDelay is how long after a logon the account is rotated.
func (p Policy) PostUseDelay() time.Duration {
	if p.PostUseDelayHours == nil {
		return DefaultPostUseHours * time.Hour
	}
	return time.Duration(*p.PostUseDelayHours) * time.Hour
}

// PolicyResponse is agent_get_admin_password_policy's answer.
type PolicyResponse struct {
	Changed bool
	Policy  Policy // set when Changed
	// RotateAfter is the per-device rotation request (reveal or Rotate
	// now); nil when there is none.
	RotateAfter *time.Time
}

// ErrBadPolicy is a policy response the agent can't use; it keeps the last
// good policy.
var ErrBadPolicy = errors.New("admin password policy rejected")

var accountNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,20}$`)

// DecodePolicyResponse parses and validates the policy poll's answer.
// Out-of-range numbers are clamped to the defaults (contract §1); a bad
// account name or a changed response without a version is rejected.
func DecodePolicyResponse(raw []byte) (PolicyResponse, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) > maxResponseBytes {
		return PolicyResponse{}, fmt.Errorf("%w: response is %d bytes", ErrBadPolicy, len(raw))
	}
	var resp struct {
		Changed     bool            `json:"changed"`
		Policy      json.RawMessage `json:"policy"`
		RotateAfter *string         `json:"rotate_after"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return PolicyResponse{}, fmt.Errorf("%w: %w", ErrBadPolicy, err)
	}
	out := PolicyResponse{Changed: resp.Changed}
	if resp.RotateAfter != nil && *resp.RotateAfter != "" {
		t, err := time.Parse(time.RFC3339, *resp.RotateAfter)
		if err != nil {
			return PolicyResponse{}, fmt.Errorf("%w: rotate_after is not an RFC 3339 time", ErrBadPolicy)
		}
		out.RotateAfter = &t
	}
	if !resp.Changed {
		return out, nil
	}
	if len(resp.Policy) == 0 || string(resp.Policy) == "null" {
		return PolicyResponse{}, fmt.Errorf("%w: changed without a policy", ErrBadPolicy)
	}
	var p Policy
	if err := json.Unmarshal(resp.Policy, &p); err != nil {
		return PolicyResponse{}, fmt.Errorf("%w: %w", ErrBadPolicy, err)
	}
	if p.Version == "" || len(p.Version) > 128 {
		return PolicyResponse{}, fmt.Errorf("%w: missing or oversized version", ErrBadPolicy)
	}
	if p.Account.Name != "" && !accountNameRe.MatchString(p.Account.Name) {
		return PolicyResponse{}, fmt.Errorf("%w: account.name is not a local account name", ErrBadPolicy)
	}
	out.Policy = normalize(p)
	return out, nil
}

// normalize clamps out-of-range values to the contract's defaults.
func normalize(p Policy) Policy {
	if p.Password.Length < MinLength || p.Password.Length > MaxLength {
		p.Password.Length = DefaultLength
	}
	if p.Password.Complexity < 1 || p.Password.Complexity > 4 {
		p.Password.Complexity = DefaultComplexity
	}
	if p.RotateEveryDays < 1 || p.RotateEveryDays > MaxRotateDays {
		p.RotateEveryDays = DefaultRotateDays
	}
	if h := p.PostUseDelayHours; h == nil || *h < 0 || *h > MaxPostUseHours {
		d := DefaultPostUseHours
		p.PostUseDelayHours = &d
	}
	return p
}

// StatusAccount is the target account as reported (no secret).
type StatusAccount struct {
	Name    string `json:"name"`
	SID     string `json:"sid"`
	Builtin bool   `json:"builtin"`
	Enabled bool   `json:"enabled"`
}

// StatusError is the last failure: a code and when, never a password.
type StatusError struct {
	Code string    `json:"code"`
	At   time.Time `json:"at"`
}

// Status is p_status (§1).
type Status struct {
	SchemaVersion     int            `json:"schema_version"`
	State             string         `json:"state"`
	ManagedBy         *string        `json:"managed_by"`
	Account           *StatusAccount `json:"account"`
	LastRotationID    string         `json:"last_rotation_id,omitempty"`
	LastRotatedAt     *time.Time     `json:"last_rotated_at"`
	NextRotationAt    *time.Time     `json:"next_rotation_at"`
	PendingRotationID *string        `json:"pending_rotation_id"`
	LastError         *StatusError   `json:"last_error"`
	PolicyVersion     string         `json:"policy_version,omitempty"`
}

// Encode returns the status JSON, failing over the server's limit.
func (s Status) Encode() ([]byte, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	if len(data) > MaxStatusBytes {
		return nil, fmt.Errorf("admin password status is %d bytes, over %d", len(data), MaxStatusBytes)
	}
	return data, nil
}

// Escrow is agent_escrow_admin_password's payload (§2). It is the only
// value that ever carries the password, and only to the server.
type Escrow struct {
	RotationID  string    `json:"rotation_id"`
	AccountName string    `json:"account_name"`
	AccountSID  string    `json:"account_sid"`
	Password    string    `json:"password"`
	Reason      string    `json:"reason"`
	GeneratedAt time.Time `json:"generated_at"`
}

// String hides the password, so a stray %v can't print it.
func (e Escrow) String() string {
	return fmt.Sprintf("Escrow{rotation_id:%s account:%s reason:%s}", e.RotationID, e.AccountName, e.Reason)
}

// GoString hides the password from %#v as well.
func (e Escrow) GoString() string { return e.String() }

// Confirm is agent_confirm_admin_password's payload (§3).
type Confirm struct {
	RotationID string     `json:"rotation_id"`
	State      string     `json:"state"`
	AppliedAt  *time.Time `json:"applied_at,omitempty"`
	ErrorCode  string     `json:"error_code,omitempty"`
}

// TaskResult is the admin-password-rotate task note's JSON line (§4).
type TaskResult struct {
	State      string `json:"state"`
	Rotated    bool   `json:"rotated"`
	RotationID string `json:"rotation_id,omitempty"`
	ErrorCode  string `json:"error_code,omitempty"`
}
