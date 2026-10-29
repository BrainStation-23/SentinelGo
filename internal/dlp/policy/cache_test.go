package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestCache_MissingIsNil(t *testing.T) {
	b, err := NewCache(filepath.Join(t.TempDir(), CacheFileName)).Load()
	if b != nil || err != nil {
		t.Errorf("Load = %v, %v; want nil, nil", b, err)
	}
}

func TestCache_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFileName)
	c := NewCache(path)
	in, err := Decode([]byte(sampleBundle))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Save(in); err != nil {
		t.Fatalf("Save: %v", err)
	}
	out, err := c.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if out.Version != in.Version || len(out.Policies) != 1 || out.Policies[0].Detectors[1].Pattern != in.Policies[0].Detectors[1].Pattern {
		t.Errorf("round trip lost data: %+v", out)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
			t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
		}
	}
	if matches, _ := filepath.Glob(filepath.Join(filepath.Dir(path), "*.tmp")); len(matches) > 0 {
		t.Errorf("temp files left behind: %v", matches)
	}
}

func TestCache_SameBundleNotRewritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), CacheFileName)
	c := NewCache(path)
	b, _ := Decode([]byte(sampleBundle))
	if err := c.Save(b); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if err := c.Save(b); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); !fi.ModTime().Equal(old) {
		t.Error("identical bundle rewrote the cache")
	}
}

// A cache this agent can't read (corrupt, or a newer schema) is an error, so
// the Manager starts as if there were none rather than enforcing garbage.
func TestCache_UnreadableIsError(t *testing.T) {
	for name, content := range map[string]string{
		"corrupt":      "{not json",
		"newer schema": `{"schema_version": 9, "version": "v"}`,
	} {
		path := filepath.Join(t.TempDir(), CacheFileName)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if b, err := NewCache(path).Load(); err == nil || b != nil {
			t.Errorf("%s: Load = %v, %v; want an error", name, b, err)
		}
	}
}
