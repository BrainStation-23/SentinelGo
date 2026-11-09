package scanworker

// The macOS scan worker account: a hidden system account created with dscl
// (UID below 500, no home, no shell), so a compromised worker can't touch
// what belongs to nobody's other users. When it can't be created, workers
// run as nobody (uid and gid -2).

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// ScanAccount is the account the scan workers run as.
const ScanAccount = "_sentinelgo-scan"

// accountPath is ScanAccount's record in the local directory.
const accountPath = "/Users/" + ScanAccount

const (
	accountUIDLow  = 400
	accountUIDHigh = 499
	nobodyID       = 0xFFFFFFFE // -2
)

var accountOnce sync.Once

// Test seam: dscl.
var runDscl = func(args ...string) ([]byte, error) {
	return exec.Command("/usr/bin/dscl", args...).CombinedOutput() // #nosec G204 -- fixed tool and arguments
}

func ensureScanAccount() {
	accountOnce.Do(func() {
		if err := createScanAccount(); err != nil {
			log.Printf("DLP: no %s account for scan workers, using nobody: %v", ScanAccount, err)
		}
	})
}

func accountIDs() (uint32, uint32, bool) {
	out, err := runDscl(".", "-read", accountPath, "UniqueID", "PrimaryGroupID")
	if err != nil {
		return 0, 0, false
	}
	var uid, gid int64 = -1, -1
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSpace(k) {
		case "UniqueID":
			uid = n
		case "PrimaryGroupID":
			gid = n
		}
	}
	if uid <= 0 || uid >= 500 || gid == -1 {
		return 0, 0, false
	}
	return uint32(uid), uint32(gid), true // #nosec G115 -- checked above; gid -2 wraps to nobody's
}

// unprivilegedIDs is ScanAccount's uid and gid, or nobody's.
func unprivilegedIDs() (uint32, uint32, error) {
	if uid, gid, ok := accountIDs(); ok {
		return uid, gid, nil
	}
	return nobodyID, nobodyID, nil
}

func createScanAccount() error {
	if _, _, ok := accountIDs(); ok {
		return nil
	}
	out, err := runDscl(".", "-list", "/Users", "UniqueID")
	if err != nil {
		return fmt.Errorf("dscl list: %w: %s", err, bytes.TrimSpace(out))
	}
	used := map[int]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			if n, err := strconv.Atoi(f[1]); err == nil {
				used[n] = true
			}
		}
	}
	uid := 0
	for n := accountUIDHigh; n >= accountUIDLow; n-- {
		if !used[n] {
			uid = n
			break
		}
	}
	if uid == 0 {
		return errors.New("no free system UID")
	}
	path := accountPath
	for _, kv := range [][2]string{
		{"UniqueID", strconv.Itoa(uid)}, {"PrimaryGroupID", "-2"}, {"UserShell", "/usr/bin/false"},
		{"NFSHomeDirectory", "/var/empty"}, {"RealName", "SentinelGo DLP scan worker"}, {"IsHidden", "1"}, {"Password", "*"},
	} {
		if out, err := runDscl(".", "-create", path, kv[0], kv[1]); err != nil {
			_, _ = runDscl(".", "-delete", path)
			return fmt.Errorf("dscl create %s: %w: %s", kv[0], err, bytes.TrimSpace(out))
		}
	}
	if _, _, ok := accountIDs(); !ok {
		return errors.New("dscl succeeded but the account isn't readable")
	}
	log.Printf("DLP: created the %s account for scan workers", ScanAccount)
	return nil
}

// RemoveScanAccount deletes ScanAccount, for `sentinelgo -uninstall`. A
// missing account is not an error.
func RemoveScanAccount() error {
	if _, _, ok := accountIDs(); !ok {
		return nil
	}
	if out, err := runDscl(".", "-delete", accountPath); err != nil {
		return fmt.Errorf("dscl delete %s: %w: %s", ScanAccount, err, bytes.TrimSpace(out))
	}
	return nil
}
