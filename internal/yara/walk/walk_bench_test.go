package walk

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// benchTree builds a profile-like tree: 50 folders of 100 small files.
func benchTree(b *testing.B) string {
	b.Helper()
	root := b.TempDir()
	for d := range 50 {
		dir := filepath.Join(root, fmt.Sprintf("dir%02d", d), "sub")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			b.Fatal(err)
		}
		for f := range 100 {
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("f%03d.bin", f)), []byte("x"), 0o644); err != nil {
				b.Fatal(err)
			}
		}
	}
	return root
}

// BenchmarkWalk measures the walk's own cost per 5,000 files: listing and
// stat (cold cache), and a scheduled rescan where every file is unchanged
// (warm cache), which is the steady state of scheduled scans.
func BenchmarkWalk(b *testing.B) {
	root := benchTree(b)
	run := func(b *testing.B, cache *Cache) {
		for b.Loop() {
			_, err := Walk(context.Background(), Options{GOOS: runtime.GOOS, Roots: []string{root}, Cache: cache, Rules: "r"},
				func(f File) error {
					if cache != nil {
						cache.Store(f.Key, "r", Clean)
					}
					return nil
				})
			if err != nil {
				b.Fatal(err)
			}
		}
	}
	b.Run("cold", func(b *testing.B) { run(b, nil) })
	b.Run("warm-cache", func(b *testing.B) {
		cache, err := OpenCache(filepath.Join(b.TempDir(), "skip.bin"), runtime.GOOS)
		if err != nil {
			b.Fatal(err)
		}
		run(b, cache) // the first iteration fills it
	})
}
