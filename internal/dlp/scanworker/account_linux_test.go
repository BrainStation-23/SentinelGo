package scanworker

import (
	"errors"
	"os"
	"os/user"
	"strings"
	"testing"
)

// fakeAccounts replaces the account commands and lookup.
type fakeAccounts struct {
	exists bool
	fail   bool
	calls  []string
}

func installFakeAccounts(t *testing.T, exists, fail bool) *fakeAccounts {
	t.Helper()
	fa := &fakeAccounts{exists: exists, fail: fail}
	prevRun, prevLookup := runAccountCmd, lookupAccount
	runAccountCmd = func(name string, args ...string) ([]byte, error) {
		fa.calls = append(fa.calls, name+" "+strings.Join(args, " "))
		if fa.fail {
			return []byte("useradd: cannot lock /etc/passwd"), errors.New("exit status 1")
		}
		fa.exists = name == "useradd"
		return nil, nil
	}
	lookupAccount = func(string) error {
		if fa.exists {
			return nil
		}
		return user.UnknownUserError(ScanAccount)
	}
	t.Cleanup(func() { runAccountCmd, lookupAccount = prevRun, prevLookup })
	return fa
}

func TestCreateScanAccount(t *testing.T) {
	fa := installFakeAccounts(t, true, false)
	if err := createScanAccount(); err != nil || len(fa.calls) != 0 {
		t.Errorf("existing account: %v %v", err, fa.calls)
	}

	fa = installFakeAccounts(t, false, false)
	if err := createScanAccount(); err != nil {
		t.Fatal(err)
	}
	if len(fa.calls) != 1 || !strings.HasPrefix(fa.calls[0], "useradd --system --user-group --no-create-home --home-dir /nonexistent --shell ") ||
		!strings.HasSuffix(fa.calls[0], " "+ScanAccount) {
		t.Errorf("calls %v", fa.calls)
	}

	installFakeAccounts(t, false, true)
	if err := createScanAccount(); err == nil || !strings.Contains(err.Error(), "cannot lock") {
		t.Errorf("failed useradd: %v", err)
	}
}

func TestRemoveScanAccount(t *testing.T) {
	fa := installFakeAccounts(t, false, false)
	if err := RemoveScanAccount(); err != nil || len(fa.calls) != 0 {
		t.Errorf("no account: %v %v", err, fa.calls)
	}
	fa = installFakeAccounts(t, true, false)
	if err := RemoveScanAccount(); err != nil || len(fa.calls) != 1 || fa.calls[0] != "userdel "+ScanAccount {
		t.Errorf("remove: %v %v", err, fa.calls)
	}
	installFakeAccounts(t, true, true)
	if err := RemoveScanAccount(); err == nil {
		t.Error("a failed userdel was not reported")
	}
}

// As root, the pool creates the account and its workers run as it.
// Needs useradd; runs in a root container or VM, removes the account after.
func TestPool_UsesScanAccount(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	requireSandbox(t)
	if _, err := user.Lookup(ScanAccount); err == nil {
		t.Skipf("%s already exists here; not touching it", ScanAccount)
	}
	t.Cleanup(func() { _ = RemoveScanAccount() })
	p := newPool(t, "serve", 1)
	f, size := tempFile(t, "TOPSECRET")
	p.Scan(t.Context(), f, size, 0)
	u, err := user.Lookup(ScanAccount)
	if err != nil {
		t.Skipf("the account couldn't be created here (%v); the pool fell back to nobody", err)
	}
	if h := p.Health(); !strings.Contains(h.Sandbox, ",user="+u.Uid) {
		t.Errorf("worker sandbox %q, want user=%s (%s)", h.Sandbox, u.Uid, ScanAccount)
	}
}
