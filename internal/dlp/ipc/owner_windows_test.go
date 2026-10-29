package ipc

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// serverIdentityOf serves addr with sddl and returns ServerIdentity as a
// client sees it. ok is false when this process may not set sddl's owner.
func serverIdentityOf(t *testing.T, sddl string) (id Identity, ok bool) {
	t.Helper()
	addr := testAddress(t)
	l, err := listen(addr, []string{sddl})
	if errors.Is(err, windows.ERROR_INVALID_OWNER) {
		return Identity{}, false
	}
	if err != nil {
		t.Fatalf("listen(%s): %v", sddl, err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		if c, err := l.Accept(); err == nil {
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := Dial(ctx, addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	id, err = ServerIdentity(c)
	if err != nil {
		t.Fatalf("ServerIdentity: %v", err)
	}
	return id, true
}

// The helper trusts the pipe by its owner, not by querying the server
// process (which a user can't do for a SYSTEM service, #292).
func TestServerIdentity_PipeOwner(t *testing.T) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := tu.User.Sid.String()

	id, _ := serverIdentityOf(t, "O:"+me+pipeDACL)
	if id.UID != me || id.User == "" || id.PID == 0 {
		t.Errorf("user-owned pipe: identity = %+v, want owner %s", id, me)
	}
	if IsPrivileged(id) {
		t.Errorf("user-owned pipe %+v counted as the service", id)
	}
	// Owned by any other user: a squatter.
	other := id
	other.UID = "S-1-5-21-1-2-3-1001"
	if TrustedServer(other) {
		t.Errorf("pipe owned by another user %+v trusted", other)
	}

	for owner, sid := range map[string]string{"SY": "S-1-5-18", "BA": "S-1-5-32-544"} {
		id, ok := serverIdentityOf(t, "O:"+owner+pipeDACL)
		if !ok {
			t.Logf("O:%s: not permitted for this account; skipped", owner)
			continue
		}
		if id.UID != sid || !TrustedServer(id) {
			t.Errorf("O:%s pipe: identity = %+v, want trusted owner %s", owner, id, sid)
		}
	}
}
