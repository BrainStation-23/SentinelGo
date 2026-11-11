package ruleset

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"sentinelgo/internal/winsec"
	"sentinelgo/internal/yara"
)

// DirName is the cache directory, next to config.json (and dlp_policy.json).
const DirName = "yara"

const (
	bundleFile = "bundle.json"
	rulesDir   = "rules"
	ruleExt    = ".yar"
)

// Cache keeps the last applied bundle and its rule sources on disk, so scans
// work after an offline reboot. Rule sources are stored by SHA-256
// (rules/<sha256>.yar) and checked again when read. The directory and every
// file are owner-only: 0700/0600 on Unix, and on Windows a protected DACL for
// SYSTEM and Administrators (winsec.SecurePath, which drops inherited ACEs).
type Cache struct{ dir string }

// NewCache returns the cache in dir (<config dir>/yara).
func NewCache(dir string) *Cache { return &Cache{dir: dir} }

// Dir is the cache's directory.
func (c *Cache) Dir() string { return c.dir }

// LoadBundle returns the cached bundle JSON, or nil when there is none.
func (c *Cache) LoadBundle() ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(c.dir, bundleFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

// Source returns the cached rule source with this SHA-256, if it is there
// and still hashes to it.
func (c *Cache) Source(sha string) ([]byte, bool) {
	if !yara.IsSHA256(sha) {
		return nil, false
	}
	data, err := os.ReadFile(filepath.Join(c.dir, rulesDir, strings.ToLower(sha)+ruleExt))
	if err != nil || len(data) > yara.MaxRulesetBytes {
		return nil, false
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]) == strings.ToLower(sha)
}

// Save stores the bundle and its sources and removes sources no longer
// listed. Each file is written to a temp file and renamed into place.
func (c *Cache) Save(raw []byte, b *yara.Bundle, sources []yara.RuleSource) error {
	rules := filepath.Join(c.dir, rulesDir)
	for _, d := range []string{c.dir, rules} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("create YARA cache: %w", err)
		}
		if err := os.Chmod(d, 0o700); err != nil {
			return err
		}
		if err := winsec.SecurePath(d); err != nil {
			return fmt.Errorf("restrict %s: %w", d, err)
		}
	}
	keep := map[string]bool{}
	byID := map[string][]byte{}
	for _, s := range sources {
		byID[s.ID] = s.Source
	}
	for _, r := range b.Rulesets {
		name := strings.ToLower(r.SHA256) + ruleExt
		keep[name] = true
		if _, ok := c.Source(r.SHA256); ok {
			continue
		}
		src, ok := byID[r.ID]
		if !ok {
			return fmt.Errorf("YARA cache: no source for ruleset %s", r.ID)
		}
		if err := writeFile(filepath.Join(rules, name), src); err != nil {
			return err
		}
	}
	if err := writeFile(filepath.Join(c.dir, bundleFile), raw); err != nil {
		return err
	}
	entries, _ := os.ReadDir(rules)
	for _, e := range entries {
		if !keep[e.Name()] {
			_ = os.Remove(filepath.Join(rules, e.Name()))
		}
	}
	return nil
}

// Clear deletes the cache (bundle disabled, or a corrupt cache).
func (c *Cache) Clear() error { return os.RemoveAll(c.dir) }

// writeFile writes data next to path, syncs it and renames it over path.
func writeFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("YARA cache: %w", err)
	}
	tmpPath := tmp.Name()
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(0o600)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmpPath, path)
	}
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("YARA cache: write %s: %w", filepath.Base(path), err)
	}
	if err := winsec.SecurePath(path); err != nil {
		log.Printf("YARA: could not restrict access to %s: %v", path, err)
	}
	return nil
}
