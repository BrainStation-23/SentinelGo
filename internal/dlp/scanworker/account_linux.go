package scanworker

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"os/user"
	"sync"

	"sentinelgo/internal/binpath"
)

// ScanAccount is the account the scan workers run as: a system account with
// no home, no shell and no other use, so a compromised worker can't touch
// anything that belongs to `nobody`'s other users.
const ScanAccount = "sentinelgo-scan"

// accountOnce makes sure the account is created at most once per run.
var accountOnce sync.Once

// Test seams: the command runner and the account lookup.
var (
	runAccountCmd = func(name string, args ...string) ([]byte, error) {
		path, ok := binpath.Lookup(name)
		if !ok {
			return nil, fmt.Errorf("%s not found", name)
		}
		return exec.Command(path, args...).CombinedOutput() // #nosec G204 -- fixed system tools and arguments
	}
	lookupAccount = func(name string) error { _, err := user.Lookup(name); return err }
)

// ensureScanAccount creates ScanAccount if it doesn't exist. The service
// does it the first time it starts workers as root, so every install
// (install.sh, -install, packages, updated devices) gets it. When it can't
// (no useradd, a directory-managed system), workers fall back to nobody.
func ensureScanAccount() {
	accountOnce.Do(func() {
		if err := createScanAccount(); err != nil {
			log.Printf("DLP: no %s account for scan workers, using nobody: %v", ScanAccount, err)
		}
	})
}

func createScanAccount() error {
	if lookupAccount(ScanAccount) == nil {
		return nil
	}
	shell := "/bin/false"
	if p, ok := binpath.Lookup("nologin"); ok {
		shell = p
	}
	out, err := runAccountCmd("useradd", "--system", "--user-group", "--no-create-home",
		"--home-dir", "/nonexistent", "--shell", shell, "--comment", "SentinelGo DLP scan worker", ScanAccount)
	if err != nil {
		return fmt.Errorf("useradd: %w: %s", err, bytes.TrimSpace(out))
	}
	if lookupAccount(ScanAccount) != nil {
		return errors.New("useradd succeeded but the account isn't visible")
	}
	log.Printf("DLP: created the %s account for scan workers", ScanAccount)
	return nil
}

// RemoveScanAccount deletes ScanAccount, for `sentinelgo -uninstall`. A
// missing account is not an error.
func RemoveScanAccount() error {
	if lookupAccount(ScanAccount) != nil {
		return nil
	}
	if out, err := runAccountCmd("userdel", ScanAccount); err != nil {
		return fmt.Errorf("userdel %s: %w: %s", ScanAccount, err, bytes.TrimSpace(out))
	}
	return nil
}
