package internal

import (
	"errors"
	"path/filepath"
	"testing"

	"sentinelgo/internal/config"
)

// The read-only build clears upload inspection's leftovers from the config
// directory at startup (#547); a failure is only logged.
func TestRemoveUploadLeftovers(t *testing.T) {
	prev := removeUploadLeftoversFn
	t.Cleanup(func() { removeUploadLeftoversFn = prev })
	var dirs []string
	removeUploadLeftoversFn = func(dir string) error { dirs = append(dirs, dir); return errors.New("nft missing") }

	dir := t.TempDir()
	removeUploadLeftovers(&config.Config{Path: filepath.Join(dir, "config.json")})
	removeUploadLeftovers(&config.Config{})
	if len(dirs) != 1 || dirs[0] != dir {
		t.Errorf("removed in %v, want once in %s", dirs, dir)
	}
}
