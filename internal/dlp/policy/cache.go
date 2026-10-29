package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"sentinelgo/internal/winsec"
)

// CacheFileName is the last-known bundle's file, next to config.json.
const CacheFileName = "dlp_policy.json"

// Cache persists the last-known bundle so enforcement resumes at boot before
// any network call, and an org-wide enabled:false survives an offline reboot.
type Cache struct {
	path string
}

// NewCache returns the cache stored at path.
func NewCache(path string) *Cache { return &Cache{path: path} }

// Path is where the cache lives.
func (c *Cache) Path() string { return c.path }

// Load returns the cached bundle, or nil when there is none. A cached bundle
// this agent can't read (corrupt, or a schema written by a newer agent) is an
// error, and the caller starts as if there were none.
func (c *Cache) Load() (*Bundle, error) {
	data, err := os.ReadFile(c.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read DLP policy cache: %w", err)
	}
	b, err := Decode(data)
	if err != nil {
		return nil, fmt.Errorf("DLP policy cache %s: %w", c.path, err)
	}
	return b, nil
}

// Save writes b atomically: a temp file in the same directory, fsync, then
// rename over the old cache. The file is 0600 on Unix and restricted to
// SYSTEM and Administrators on Windows.
func (c *Cache) Save(b *Bundle) error {
	data, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("encode DLP policy: %w", err)
	}
	if old, err := os.ReadFile(c.path); err == nil && bytes.Equal(old, data) {
		return nil
	}
	dir := filepath.Dir(c.path)
	tmp, err := os.CreateTemp(dir, "dlp_policy-*.tmp")
	if err != nil {
		return fmt.Errorf("create DLP policy temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if err := writeSynced(tmp, data); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, c.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replace DLP policy cache: %w", err)
	}
	if err := winsec.SecurePath(c.path); err != nil {
		log.Printf("DLP: could not restrict access to %s: %v", c.path, err)
	}
	return nil
}

// writeSynced writes data to f, makes it owner-only, flushes it to disk and
// closes it.
func writeSynced(f *os.File, data []byte) error {
	_, err := f.Write(data)
	if err == nil {
		err = f.Chmod(0o600)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("write DLP policy cache: %w", err)
	}
	return nil
}
