package walk

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"syscall"
	"testing"
	"time"
)

// tree creates files (relative path -> content) under a temp dir.
func tree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// collect walks o and returns the files handed out, relative to base.
func collect(t *testing.T, base string, o Options) ([]string, Stats, error) {
	t.Helper()
	if o.GOOS == "" {
		o.GOOS = runtime.GOOS
	}
	var got []string
	st, err := Walk(context.Background(), o, func(f File) error {
		if base == "" {
			got = append(got, f.Path)
			return nil
		}
		rel, err := filepath.Rel(base, f.Path)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, filepath.ToSlash(rel))
		return nil
	})
	return got, st, err
}

func TestWalk_OrderAndCounts(t *testing.T) {
	root := tree(t, map[string]string{"b.txt": "b", "a/2.txt": "2", "a/1.txt": "1", "a/sub/x": "x", "c": "c"})
	got, st, err := collect(t, root, Options{Roots: []string{root}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a/1.txt", "a/2.txt", "a/sub/x", "b.txt", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("files = %q, want %q", got, want)
	}
	if st.Files != 5 || st.FilesSkipped() != 0 || st.Errors != 0 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestWalk_SymlinkLoopNotFollowed(t *testing.T) {
	root := tree(t, map[string]string{"dir/file": "x", "outside/secret": "s"})
	if err := os.Symlink(root, filepath.Join(root, "dir", "loop")); err != nil {
		t.Skipf("can't create symlinks here: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "outside", "secret"), filepath.Join(root, "dir", "filelink")); err != nil {
		t.Fatal(err)
	}
	got, st, err := collect(t, root, Options{Roots: []string{filepath.Join(root, "dir")}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"dir/file"}) || st.Skipped[SkipLink] != 2 {
		t.Fatalf("files = %q, stats = %+v", got, st)
	}
	// A root that is itself a link isn't followed either.
	_, st, _ = collect(t, root, Options{Roots: []string{filepath.Join(root, "dir", "loop")}})
	if st.Files != 0 || st.Skipped[SkipLink] != 1 {
		t.Fatalf("link root: %+v", st)
	}
}

func TestWalk_JunctionNotFollowed(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("junctions are Windows-only")
	}
	root := tree(t, map[string]string{"dir/file": "x", "target/secret": "s"})
	out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(root, "dir", "junction"), filepath.Join(root, "target")).CombinedOutput()
	if err != nil {
		t.Skipf("mklink /J: %v: %s", err, out)
	}
	got, st, err := collect(t, root, Options{Roots: []string{filepath.Join(root, "dir")}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"dir/file"}) || st.Skipped[SkipLink] != 1 {
		t.Fatalf("files = %q, stats = %+v", got, st)
	}
}

func TestWalk_ExcludedTooLargeDepth(t *testing.T) {
	root := tree(t, map[string]string{
		"keep/a": "a", "skipme/b": "b", "big": "0123456789", "d1/d2/d3/deep": "d", "d1/shallow": "s",
	})
	x := NewExcluder([]string{filepath.Join(root, "skipme")}, "", hostEnv())
	got, st, err := collect(t, root, Options{Roots: []string{root}, Exclude: x, MaxFileBytes: 5, MaxDepth: 2})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"d1/shallow", "keep/a"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("files = %q, want %q", got, want)
	}
	if st.Skipped[SkipExcluded] != 1 || st.Skipped[SkipTooLarge] != 1 || st.Skipped[SkipTooDeep] != 1 {
		t.Fatalf("skipped = %v", st.Skipped)
	}
}

func TestWalk_UnchangedFilesSkipped(t *testing.T) {
	root := tree(t, map[string]string{"a": "a", "b": "b", "c": "c"})
	cache, err := OpenCache(filepath.Join(t.TempDir(), "skip.bin"), runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	scan := func(rules string) []string {
		t.Helper()
		cache.BeginScan()
		var got []string
		_, err := Walk(context.Background(), Options{GOOS: runtime.GOOS, Roots: []string{root}, Cache: cache, Rules: rules},
			func(f File) error {
				got = append(got, filepath.Base(f.Path))
				cache.Store(f.Key, rules, Clean)
				return nil
			})
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := scan("r1"); len(got) != 3 {
		t.Fatalf("first scan: %q", got)
	}
	if got := scan("r1"); len(got) != 0 {
		t.Fatalf("unchanged files rescanned: %q", got)
	}
	// A changed file is scanned again.
	later := time.Now().Add(time.Hour)
	if err := os.WriteFile(filepath.Join(root, "b"), []byte("bb"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(root, "b"), later, later); err != nil {
		t.Fatal(err)
	}
	if got := scan("r1"); !reflect.DeepEqual(got, []string{"b"}) {
		t.Fatalf("after a change: %q", got)
	}
	// New rules: everything is scanned again.
	if got := scan("r2"); len(got) != 3 {
		t.Fatalf("after a rules change: %q", got)
	}
	// It survives a restart.
	if err := cache.Save(); err != nil {
		t.Fatal(err)
	}
	if cache, err = OpenCache(cache.path, runtime.GOOS); err != nil {
		t.Fatal(err)
	}
	if got := scan("r2"); len(got) != 0 {
		t.Fatalf("after reload: %q", got)
	}
}

func TestWalk_Mounts(t *testing.T) {
	root := tree(t, map[string]string{"local/a": "a", "share/b": "b", "usb/c": "c"})
	mounts := []Mount{{Path: filepath.Join(root, "share"), Network: true}, {Path: filepath.Join(root, "usb")}}
	got, st, err := collect(t, root, Options{Roots: []string{root}, Mounts: mounts})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"local/a"}) || st.Skipped[SkipNetwork] != 1 || st.Skipped[SkipRemovable] != 1 {
		t.Fatalf("files = %q, stats = %+v", got, st)
	}
	got, _, _ = collect(t, root, Options{Roots: []string{root}, Mounts: mounts, IncludeNetwork: true, IncludeRemovable: true})
	if len(got) != 3 {
		t.Fatalf("included mounts: %q", got)
	}
	// A root inside an excluded mount is skipped whole.
	_, st, _ = collect(t, root, Options{Roots: []string{filepath.Join(root, "usb")}, Mounts: mounts})
	if st.Files != 0 || st.Skipped[SkipRemovable] != 1 {
		t.Fatalf("root on removable: %+v", st)
	}
}

func TestMountSkip_Firmlinked(t *testing.T) {
	w := &walker{o: Options{GOOS: "darwin", Mounts: []Mount{{Path: "/Volumes/USB"}, {Path: "/Volumes/share", Network: true}}},
		mounts: map[string]Mount{}}
	for _, m := range w.o.Mounts {
		w.mounts[w.fold(m.Path)] = m
	}
	for p, want := range map[string]string{
		"/Volumes/USB":                             SkipRemovable,
		"/System/Volumes/Data/Volumes/USB":         SkipRemovable,
		"/System/Volumes/Data/Volumes/share":       SkipNetwork,
		"/System/Volumes/Data/Volumes/Macintosh":   "",
		"/System/Volumes/Data/Users/a/Volumes/USB": "",
	} {
		if got, _ := w.mountSkip(p, false); got != want {
			t.Errorf("mountSkip(%q) = %q, want %q", p, got, want)
		}
	}
}

// stopAfter is a Guard that allows n files per walk.
type stopAfter struct{ n, used int }

func (s *stopAfter) Wait(context.Context) error {
	if s.used >= s.n {
		return ErrLimitReached
	}
	s.used++
	return nil
}

func TestWalk_ResumeFromCheckpoint(t *testing.T) {
	r1 := tree(t, map[string]string{"a/1": "1", "a/2": "2", "a/b/3": "3", "a-x": "4", "b": "5"})
	r2 := tree(t, map[string]string{"x": "6", "y/z": "7"})
	roots := []string{r1, r2}
	all, _, err := collect(t, "", Options{Roots: roots})
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	var cp *Checkpoint
	for range 10 {
		got, st, err := collect(t, "", Options{Roots: roots, Guard: &stopAfter{n: 2}, Resume: cp})
		seen = append(seen, got...)
		if err == nil {
			break
		}
		if !errors.Is(err, ErrPartial) || st.Checkpoint == nil {
			t.Fatalf("err = %v, checkpoint = %v", err, st.Checkpoint)
		}
		cp = st.Checkpoint
	}
	if !reflect.DeepEqual(seen, all) {
		t.Fatalf("resumed walks saw\n%q\nwant\n%q", seen, all)
	}
	// A checkpoint for other roots is ignored: the walk starts over.
	got, _, err := collect(t, "", Options{Roots: []string{r2}, Resume: &Checkpoint{RootsKey: RootsKey(roots), Root: 1, Path: filepath.Join(r2, "x")}})
	if err != nil || len(got) != 2 {
		t.Fatalf("stale checkpoint: %q, %v", got, err)
	}
}

func TestWalk_StopsOnCallbackErrorAndContext(t *testing.T) {
	root := tree(t, map[string]string{"a": "a", "b": "b"})
	boom := errors.New("boom")
	st, err := Walk(context.Background(), Options{GOOS: runtime.GOOS, Roots: []string{root}}, func(File) error { return boom })
	if !errors.Is(err, boom) || st.Files != 0 {
		t.Fatalf("err = %v, stats = %+v", err, st)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Walk(ctx, Options{GOOS: runtime.GOOS, Roots: []string{root}}, func(File) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled walk: %v", err)
	}
}

// TCC: on macOS without Full Disk Access, protected folders fail with
// EPERM. They are counted as skipped (tcc_denied), not as errors.
func TestWalk_TCCDeniedIsASkip(t *testing.T) {
	oldRead, oldLstat := readDir, lstat
	t.Cleanup(func() { readDir, lstat = oldRead, oldLstat })
	lstat = func(string) (fs.FileInfo, error) { return fakeInfo{fakeEntry{name: "a", dir: true}}, nil }
	readDir = func(dir string) ([]os.DirEntry, error) {
		switch dir {
		case "/Users/a":
			return []os.DirEntry{fakeEntry{name: "Downloads", dir: true}, fakeEntry{name: "notes.txt"}, fakeEntry{name: "proj", dir: true}}, nil
		case "/Users/a/Downloads":
			return nil, &fs.PathError{Op: "open", Path: dir, Err: syscall.EPERM}
		case "/Users/a/proj":
			return nil, &fs.PathError{Op: "open", Path: dir, Err: syscall.EACCES}
		}
		return nil, fs.ErrNotExist
	}
	st, err := Walk(context.Background(), Options{GOOS: "darwin", Roots: []string{"/Users/a"}}, func(File) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !st.TCCDenied || st.Skipped[SkipTCCDenied] != 1 || st.Errors != 1 || st.Files != 1 {
		t.Fatalf("stats = %+v", st)
	}
	// The same EPERM elsewhere is an ordinary error.
	st, _ = Walk(context.Background(), Options{GOOS: "linux", Roots: []string{"/Users/a"}}, func(File) error { return nil })
	if st.TCCDenied || st.Errors != 2 {
		t.Fatalf("linux stats = %+v", st)
	}
}

func TestOpen(t *testing.T) {
	root := tree(t, map[string]string{"a": "content", "b": "other"})
	var files []File
	if _, err := Walk(context.Background(), Options{GOOS: runtime.GOOS, Roots: []string{root}}, func(f File) error {
		files = append(files, f)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	f, err := Open(files[0])
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, _ := f.Read(buf)
	_ = f.Close()
	if string(buf[:n]) != "content" {
		t.Fatalf("read %q", buf[:n])
	}
	// Replaced by a folder after the listing: refused.
	if err := os.Remove(files[1].Path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(files[1].Path, 0o755); err != nil {
		t.Fatal(err)
	}
	if f, err := Open(files[1]); err == nil {
		_ = f.Close()
		t.Fatal("opened a folder swapped in for a file")
	}
}

func TestOpen_RefusesSwappedLinkOrFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file identity check")
	}
	root := tree(t, map[string]string{"a": "a", "target": "secret"})
	var f File
	_, _ = Walk(context.Background(), Options{GOOS: runtime.GOOS, Roots: []string{filepath.Join(root, "a")}}, func(x File) error {
		f = x
		return nil
	})
	// Replaced by a symlink: O_NOFOLLOW refuses it.
	_ = os.Remove(f.Path)
	if err := os.Symlink(filepath.Join(root, "target"), f.Path); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(f); !errors.Is(err, ErrChanged) {
		t.Fatalf("symlink: err = %v, want ErrChanged", err)
	}
	// Replaced by another file (written beside it and renamed over it, so
	// the file system can't reuse the inode): the identity differs.
	_ = os.Remove(f.Path)
	if err := os.WriteFile(f.Path, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _ = Walk(context.Background(), Options{GOOS: runtime.GOOS, Roots: []string{f.Path}}, func(x File) error {
		f = x
		return nil
	})
	if err := os.WriteFile(f.Path+".new", []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(f.Path+".new", f.Path); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(f); !errors.Is(err, ErrChanged) {
		t.Fatalf("replaced file: err = %v, want ErrChanged", err)
	}
}

func TestCompareWalkOrder(t *testing.T) {
	paths := []string{"/r/a-x", "/r/a/b/3", "/r/a", "/r/b", "/r/a/1"}
	slices.SortFunc(paths, func(a, b string) int { return compareWalkOrder(a, b, "/") })
	if want := []string{"/r/a", "/r/a/1", "/r/a/b/3", "/r/a-x", "/r/b"}; !reflect.DeepEqual(paths, want) {
		t.Fatalf("order = %q, want %q", paths, want)
	}
}

// hostEnv is the real device's Env, for tests on real files.
func hostEnv() Env {
	return Env{GOOS: runtime.GOOS, Getenv: os.Getenv, ReadDir: os.ReadDir,
		Exists: func(p string) bool { _, err := os.Lstat(p); return err == nil }}
}
