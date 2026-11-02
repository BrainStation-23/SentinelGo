package filedlp

import (
	"bufio"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// procRoot is /proc; tests point it at a fixture.
var procRoot = "/proc"

var (
	userNamesMu sync.Mutex
	userNames   = map[string]string{}
)

// processInfo describes pid from /proc. The writer may already have exited:
// whatever can't be read stays empty.
func processInfo(pid int) Process {
	p := Process{PID: pid}
	dir := filepath.Join(procRoot, strconv.Itoa(pid))
	if b, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil { // #nosec G304 -- procfs
		p.Name = strings.TrimSpace(string(b))
	}
	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		p.Exe = strings.TrimSuffix(exe, " (deleted)")
	}
	if f, err := os.Open(filepath.Join(dir, "status")); err == nil { // #nosec G304 -- procfs
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if rest, ok := strings.CutPrefix(sc.Text(), "Uid:"); ok {
				if fields := strings.Fields(rest); len(fields) > 0 {
					p.UID = fields[0] // real uid: who ran it, not a setuid owner
				}
				break
			}
		}
		_ = f.Close()
	}
	if p.UID != "" {
		p.User = userName(p.UID)
	}
	return p
}

// userName maps a uid to its account name (the uid itself if unknown).
func userName(uid string) string {
	userNamesMu.Lock()
	defer userNamesMu.Unlock()
	if n, ok := userNames[uid]; ok {
		return n
	}
	name := uid
	if u, err := user.LookupId(uid); err == nil {
		name = u.Username
	}
	if len(userNames) < 1024 {
		userNames[uid] = name
	}
	return name
}
