//go:build windows

package adminpassword

import (
	"errors"
	"strings"
	"testing"
)

// These tests only read the local SAM and registry; none sets a password.

func TestWindowsHost_BuiltinAdministrator(t *testing.T) {
	h := NewHost()
	a, err := h.Account("")
	if err != nil {
		t.Fatalf("built-in Administrator: %v", err)
	}
	if !a.Builtin || !strings.HasPrefix(a.SID, "S-1-5-21-") || !strings.HasSuffix(a.SID, "-500") || a.Name == "" {
		t.Fatalf("account %+v", a)
	}
	if a.PasswordLastSet.IsZero() {
		t.Fatal("no password-last-set time")
	}
	b, err := h.AccountBySID(a.SID)
	if err != nil || b.Name != a.Name || b.SID != a.SID {
		t.Fatalf("by SID: %+v, %v", b, err)
	}
	c, err := h.Account(a.Name)
	if err != nil || c.SID != a.SID {
		t.Fatalf("by name: %+v, %v", c, err)
	}
}

func TestWindowsHost_MissingAccount(t *testing.T) {
	_, err := NewHost().Account("sg-no-such-user")
	if !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("err = %v, want ErrAccountNotFound", err)
	}
	if _, err := NewHost().AccountBySID("S-1-5-21-1-2-3-999999"); !errors.Is(err, ErrAccountNotFound) {
		t.Fatalf("by SID: err = %v, want ErrAccountNotFound", err)
	}
}

func TestWindowsHost_ManagedByReads(t *testing.T) {
	by, err := NewHost().ManagedBy()
	if err != nil {
		t.Fatalf("ManagedBy: %v", err)
	}
	switch by {
	case "", ManagedByWindowsLAPS, ManagedByLegacyLAPS:
	default:
		t.Fatalf("managed_by %q", by)
	}
	t.Logf("managed_by=%q unsupported=%q", by, NewHost().Unsupported())
}
