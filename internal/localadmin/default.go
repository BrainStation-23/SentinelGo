package localadmin

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

var (
	defaultsMu sync.Mutex
	defaults   = map[string]*Manager{}
)

// ForConfigDir returns the process's manager for a config directory, built
// for this OS on first use. The task handler and the service's expiry loop
// share it, so they never write the store at the same time.
func ForConfigDir(dir string) (*Manager, error) {
	defaultsMu.Lock()
	defer defaultsMu.Unlock()
	dir = filepath.Clean(dir)
	if m, ok := defaults[dir]; ok {
		return m, nil
	}
	group, err := ForOS(runtime.GOOS, Exec)
	if err != nil {
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	m := NewManager(StorePath(dir), group, BackupFor(runtime.GOOS, Exec, exe))
	defaults[dir] = m
	return m, nil
}
