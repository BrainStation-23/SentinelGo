package walk

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCache_SaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "skip.bin")
	c, err := OpenCache(path, "linux")
	if err != nil || c.Len() != 0 {
		t.Fatalf("missing cache: %v, %d entries", err, c.Len())
	}
	k := Key{Path: "/home/a/x", Size: 3, MTime: 10, Change: 11}
	c.BeginScan()
	c.Store(k, "rules", Matched)
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	c2, err := OpenCache(path, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if r, ok := c2.Lookup(k, "rules"); !ok || r != Matched {
		t.Fatalf("Lookup = %v, %v", r, ok)
	}
	for _, other := range []Key{
		{Path: "/home/a/x", Size: 4, MTime: 10, Change: 11},
		{Path: "/home/a/x", Size: 3, MTime: 12, Change: 11},
		{Path: "/home/a/x", Size: 3, MTime: 10, Change: 99},
		{Path: "/home/a/X", Size: 3, MTime: 10, Change: 11}, // case-sensitive on Linux
	} {
		if _, ok := c2.Lookup(other, "rules"); ok {
			t.Errorf("hit for changed key %+v", other)
		}
	}
	if _, ok := c2.Lookup(k, "other rules"); ok {
		t.Error("hit under other rules")
	}
	if runtime.GOOS != "windows" {
		for _, p := range []string{path, filepath.Dir(path)} {
			info, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm()&0o077 != 0 {
				t.Errorf("%s is %v, want owner-only", p, info.Mode().Perm())
			}
		}
	}
	// No paths in the file, only hashes.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("/home/a")) {
		t.Error("cache file contains a path")
	}
}

func TestCache_WindowsFoldsCase(t *testing.T) {
	c, _ := OpenCache(filepath.Join(t.TempDir(), "skip.bin"), "windows")
	c.Store(Key{Path: `C:\Users\A\x.exe`, Size: 1}, "r", Clean)
	if _, ok := c.Lookup(Key{Path: `c:\users\a\X.EXE`, Size: 1}, "r"); !ok {
		t.Fatal("Windows paths compared case-sensitively")
	}
}

func TestCache_CorruptStartsEmpty(t *testing.T) {
	for name, data := range map[string][]byte{
		"garbage":   []byte("not a cache"),
		"version":   append([]byte("SGYC"), 9, 0, 0, 0, 0, 0, 0, 0, 0),
		"truncated": append([]byte("SGYC"), 1, 1, 0, 0, 0, 5, 0, 0, 0, 1, 2, 3),
	} {
		path := filepath.Join(t.TempDir(), "skip.bin")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := OpenCache(path, "linux")
		if err == nil || c == nil || c.Len() != 0 {
			t.Errorf("%s: err = %v, cache = %v", name, err, c)
			continue
		}
		// The next save replaces it.
		c.Store(Key{Path: "/x"}, "r", Clean)
		if err := c.Save(); err != nil {
			t.Fatal(err)
		}
		if c2, err := OpenCache(path, "linux"); err != nil || c2.Len() != 1 {
			t.Errorf("%s: after save: %v, %d", name, err, c2.Len())
		}
	}
}

func TestCache_TrimKeepsRecentlySeen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "skip.bin")
	c, _ := OpenCache(path, "linux")
	c.SetMaxEntries(3)
	key := func(i int) Key { return Key{Path: fmt.Sprintf("/f%d", i)} }
	c.BeginScan()
	for i := range 3 {
		c.Store(key(i), "r", Clean)
	}
	c.BeginScan()
	c.Lookup(key(0), "r") // seen again
	c.Store(key(3), "r", Clean)
	c.Store(key(4), "r", Clean)
	if err := c.Save(); err != nil {
		t.Fatal(err)
	}
	c2, _ := OpenCache(path, "linux")
	if c2.Len() != 3 {
		t.Fatalf("%d entries, want 3", c2.Len())
	}
	for _, i := range []int{0, 3, 4} {
		if _, ok := c2.Lookup(key(i), "r"); !ok {
			t.Errorf("recent entry %d dropped", i)
		}
	}
}
