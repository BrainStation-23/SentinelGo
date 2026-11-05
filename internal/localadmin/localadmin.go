// Package localadmin adds accounts to and removes them from the device's
// local administrators, and removes time-limited grants at their expiry by
// itself, even offline (#388). It is the native side of the console's
// local-admin-add / local-admin-remove commands (Compliance-OS#715), and
// behaves like their scripts: the same group per OS, the same matching, the
// same guards and the same one-line JSON result.
//
// Windows: the Administrators group by SID (S-1-5-32-544). macOS: admin.
// Linux: sudo or wheel (and admin on removal).
package localadmin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Request is one add or remove, from the task payload.
type Request struct {
	Member    string     // "alice", "CONTOSO\\alice", "AzureAD\\bob@contoso.com"
	SID       string     // Windows; preferred over Member when set
	Source    string     // local | domain | entra ("" means local)
	SignOut   bool       // remove only: end the account's sessions
	GrantID   string     // the console's grant; "" for a plain command
	ExpiresAt *time.Time // add only: remove the rights at this time
}

// Outcome mirrors the scripts' JSON line.
type Outcome struct {
	Success   bool   `json:"Success"`
	State     string `json:"State"` // added | already | removed | absent
	Member    string `json:"Member"`
	Group     string `json:"Group,omitempty"`
	SignedOut *int   `json:"SignedOut,omitempty"`
	Note      string `json:"Note,omitempty"` // e.g. why the backup task wasn't created
}

// JSON is the outcome as the task note.
func (o Outcome) JSON() string {
	b, _ := json.Marshal(o)
	return string(b)
}

// Member states, as the scripts report them.
const (
	StateAdded   = "added"
	StateAlready = "already"
	StateRemoved = "removed"
	StateAbsent  = "absent"
)

// Guard errors: the operation is refused and nothing changes.
var (
	ErrNoAccount     = errors.New("no account given (member)")
	ErrBadName       = errors.New("not an account name")
	ErrBuiltinAdmin  = errors.New("the built-in Administrator account is not changed")
	ErrSystemAccount = errors.New("system accounts are not changed")
	ErrRoot          = errors.New("root is not changed")
	ErrOwnAccount    = errors.New("the account the agent runs as is not changed")
	ErrAlreadyAdmin  = errors.New("the account is already an administrator: a time-limited grant would remove standing rights when it ends")
)

// lastAdminError is returned when removing the account would leave no
// administrator.
func lastAdminError(name string) error {
	return fmt.Errorf("%s is the last administrator", name)
}

var (
	unixNameRe = regexp.MustCompile(`^[A-Za-z0-9._@-]+$`)
	sidRe      = regexp.MustCompile(`^S-1-[0-9]+(-[0-9]+)+$`)
	grantIDRe  = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

// bareName is the part after the last backslash: "CONTOSO\alice" → "alice".
func bareName(s string) string {
	if i := strings.LastIndexByte(s, '\\'); i >= 0 {
		return s[i+1:]
	}
	return s
}

// unixName validates a macOS/Linux account name the way the scripts do,
// and also refuses a leading '-' so it can't be read as a flag.
func unixName(member string) (string, error) {
	m := bareName(strings.TrimSpace(member))
	if m == "" {
		return "", ErrNoAccount
	}
	if !unixNameRe.MatchString(m) || strings.HasPrefix(m, "-") {
		return "", ErrBadName
	}
	return m, nil
}

// ValidGrantID reports whether id can name files and scheduled tasks.
func ValidGrantID(id string) bool { return grantIDRe.MatchString(id) }

// ParseRequest reads a local-admin-add / local-admin-remove payload:
// {member, sid, source, sign_out, grant_id, expires_at}. Unknown keys are
// ignored, as the scripts ignore them.
func ParseRequest(p map[string]interface{}, add bool) (Request, error) {
	str := func(k string) (string, error) {
		v, ok := p[k]
		if !ok || v == nil {
			return "", nil
		}
		s, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("payload.%s must be a string", k)
		}
		return strings.TrimSpace(s), nil
	}
	var r Request
	var err error
	if r.Member, err = str("member"); err != nil {
		return r, err
	}
	if r.SID, err = str("sid"); err != nil {
		return r, err
	}
	if r.Source, err = str("source"); err != nil {
		return r, err
	}
	if r.GrantID, err = str("grant_id"); err != nil {
		return r, err
	}
	if r.Member == "" && r.SID == "" {
		return r, ErrNoAccount
	}
	if strings.ContainsFunc(r.Member, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
		return r, ErrBadName
	}
	if r.SID != "" && !sidRe.MatchString(r.SID) {
		return r, fmt.Errorf("payload.sid is not a SID")
	}
	switch strings.ToLower(r.Source) {
	case "", "local", "domain", "entra":
		r.Source = strings.ToLower(r.Source)
	default:
		return r, fmt.Errorf("payload.source must be local, domain or entra")
	}
	if r.GrantID != "" && !ValidGrantID(r.GrantID) {
		return r, fmt.Errorf("payload.grant_id is not a grant id")
	}
	if v, ok := p["sign_out"].(bool); ok {
		r.SignOut = v
	}
	exp, err := str("expires_at")
	if err != nil {
		return r, err
	}
	if exp != "" {
		if !add {
			return r, fmt.Errorf("payload.expires_at only applies to local-admin-add")
		}
		t, err := time.Parse(time.RFC3339, exp)
		if err != nil {
			return r, fmt.Errorf("payload.expires_at is not an RFC 3339 time")
		}
		if r.GrantID == "" {
			return r, fmt.Errorf("payload.grant_id is required with expires_at")
		}
		r.ExpiresAt = &t
	}
	return r, nil
}

// Group is the platform's administrator group operations.
type Group interface {
	// IsMember reports whether the request's account is an administrator.
	IsMember(ctx context.Context, r Request) (bool, error)
	// Add makes the account an administrator.
	Add(ctx context.Context, r Request) (Outcome, error)
	// Remove takes the rights away, with the guards, and signs the account
	// out when r.SignOut.
	Remove(ctx context.Context, r Request) (Outcome, error)
}

// ForOS returns the group operations for goos, running commands with run.
func ForOS(goos string, run Runner) (Group, error) {
	self := currentUser()
	switch goos {
	case "windows":
		return &windowsGroup{run: run, signOut: signOutWindows}, nil
	case "darwin":
		return &darwinGroup{run: run, self: self}, nil
	case "linux":
		return &linuxGroup{run: run, self: self}, nil
	}
	return nil, fmt.Errorf("local admin rights aren't supported on %s", goos)
}
