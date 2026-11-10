package packages

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const lockV3 = `{"lockfileVersion":3,"packages":{"":{},"node_modules/keyv":{"version":"4.5.4"}}}`

func pinHomes(t *testing.T, homes ...string) {
	t.Helper()
	orig := userHomeDirs
	t.Cleanup(func() { userHomeDirs = orig })
	userHomeDirs = func() []string { return homes }
}

func names(pkgs []Package) map[string]Package {
	out := map[string]Package{}
	for _, p := range pkgs {
		out[p.Name+"@"+p.Version+" "+p.Location] = p
	}
	return out
}

func TestProjectScan_HomeTree(t *testing.T) {
	alice := filepath.Join(t.TempDir(), "alice")
	app := filepath.Join(alice, "code", "app")
	write(t, filepath.Join(app, "package-lock.json"), lockV3)
	write(t, filepath.Join(app, "requirements.txt"), "requests==2.31.0\n")
	write(t, filepath.Join(app, "node_modules", "dep", "package-lock.json"), lockV3)  // skipped dir
	write(t, filepath.Join(app, ".git", "x", "package-lock.json"), lockV3)            // hidden dir
	write(t, filepath.Join(alice, "a", "b", "c", "d", "e", "f", "g", "yarn.lock"), "") // deeper than 6
	write(t, filepath.Join(alice, "composer.lock"), `{"packages":[{"name":"a/b","version":"v1.0.0"}]}`)
	pinHomes(t, alice)

	p := newProjectScanner()
	pkgs, complete, more := p.run(context.Background(), Settings{ProjectScan: true, MaxDepth: 6})
	if !complete || more {
		t.Errorf("complete=%v more=%v, want a finished pass", complete, more)
	}
	got := names(pkgs)
	lock := filepath.Join(app, "package-lock.json")
	for _, k := range []string{
		"keyv@4.5.4 " + lock,
		"requests@2.31.0 " + filepath.Join(app, "requirements.txt"),
		"a/b@1.0.0 " + filepath.Join(alice, "composer.lock"),
	} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing %q in %v", k, got)
		}
	}
	if len(got) != 3 {
		t.Errorf("got %d packages, want 3: %v", len(got), got)
	}
	if k := got["keyv@4.5.4 "+lock]; k.Scope != ScopeProject || k.User != "alice" || k.Ecosystem != EcosystemNPM {
		t.Errorf("keyv = %+v", k)
	}
}

func TestProjectScan_DepthAndRoots(t *testing.T) {
	dir := t.TempDir()
	srv := filepath.Join(dir, "srv")
	write(t, filepath.Join(srv, "x", "package-lock.json"), lockV3)
	write(t, filepath.Join(srv, "x", "y", "package-lock.json"), lockV3)
	pinHomes(t, filepath.Join(dir, "home")) // not walked: roots are configured

	p := newProjectScanner()
	pkgs, _, _ := p.run(context.Background(), Settings{ProjectScan: true, Roots: []string{srv, "relative/ignored"}, MaxDepth: 1})
	if len(pkgs) != 1 || pkgs[0].Location != filepath.Join(srv, "x", "package-lock.json") || pkgs[0].User != "" {
		t.Errorf("depth 1 = %+v", pkgs)
	}
}

func TestProjectScan_ResumesAcrossRuns(t *testing.T) {
	home := filepath.Join(t.TempDir(), "bob")
	for _, d := range []string{"p1", "p2", "p3"} {
		write(t, filepath.Join(home, d, "package-lock.json"), lockV3)
	}
	pinHomes(t, home)
	p := newProjectScanner()
	s := Settings{ProjectScan: true, MaxDepth: 6}

	// Stop the first run after the root directory: the pass isn't done.
	ctx, cancel := context.WithCancel(context.Background())
	p.mu.Lock()
	p.key = "6\x00"
	p.startPass(nil)
	p.visit(p.queue[0], 6)
	p.queue = p.queue[1:]
	p.mu.Unlock()
	cancel()
	pkgs, complete, more := p.run(ctx, s)
	if complete || !more || len(pkgs) != 0 {
		t.Fatalf("interrupted first pass = %d pkgs, complete=%v more=%v", len(pkgs), complete, more)
	}

	// The next run finishes the same pass.
	pkgs, complete, more = p.run(context.Background(), s)
	if !complete || more || len(pkgs) != 3 {
		t.Fatalf("resumed pass = %d pkgs, complete=%v more=%v", len(pkgs), complete, more)
	}

	// A later pass that is interrupted reports the last pass: still complete.
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	pkgs, complete, more = p.run(ctx, s)
	if !complete || !more || len(pkgs) != 3 {
		t.Errorf("interrupted second pass = %d pkgs, complete=%v more=%v", len(pkgs), complete, more)
	}
}

func TestProjectScan_SettingsChangeRestarts(t *testing.T) {
	home := filepath.Join(t.TempDir(), "carol")
	write(t, filepath.Join(home, "a", "package-lock.json"), lockV3)
	pinHomes(t, home)
	p := newProjectScanner()
	if pkgs, _, _ := p.run(context.Background(), Settings{ProjectScan: true, MaxDepth: 6}); len(pkgs) != 1 {
		t.Fatalf("first pass = %v", pkgs)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A new depth starts over: the old pass can't stand in for it.
	if _, complete, _ := p.run(ctx, Settings{ProjectScan: true, MaxDepth: 2}); complete {
		t.Error("an interrupted pass under new settings reported complete")
	}
}

func TestProjectScan_SkipsSymlinkedDirs(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "dave")
	outside := filepath.Join(dir, "outside")
	write(t, filepath.Join(outside, "package-lock.json"), lockV3)
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, "link")); err != nil {
		t.Skipf("symlinks not available: %v", err)
	}
	pinHomes(t, home)
	if pkgs, _, _ := newProjectScanner().run(context.Background(), Settings{ProjectScan: true}); len(pkgs) != 0 {
		t.Errorf("followed a symlink: %+v", pkgs)
	}
}

func TestProjectScan_OversizedLockfileSkipped(t *testing.T) {
	home := filepath.Join(t.TempDir(), "erin")
	lock := filepath.Join(home, "package-lock.json")
	write(t, lock, "")
	if err := os.Truncate(lock, maxLockfileBytes+1); err != nil {
		t.Fatal(err)
	}
	pinHomes(t, home)
	pkgs, complete, _ := newProjectScanner().run(context.Background(), Settings{ProjectScan: true})
	if len(pkgs) != 0 || !complete {
		t.Errorf("oversized lockfile = %v, complete=%v", pkgs, complete)
	}
}

func TestDefaultCollector_ProjectScanOff(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "frank")
	write(t, filepath.Join(home, "app", "package-lock.json"), lockV3)
	pinRoots(t, filepath.Join(dir, "sys"), []string{home}, nil)

	c := DefaultCollector()
	if got := c(context.Background(), Settings{Enabled: true}); len(got.Packages) != 0 || !got.Complete {
		t.Errorf("project scan off = %+v", got)
	}
	got := c(context.Background(), Settings{Enabled: true, ProjectScan: true})
	if len(got.Packages) != 1 || !got.Complete || got.More {
		t.Errorf("project scan on = %+v", got)
	}
}

func TestOwnerHome(t *testing.T) {
	homes := []string{filepath.Join("/", "home", "al"), filepath.Join("/", "home", "alice")}
	for path, want := range map[string]string{
		filepath.Join("/", "home", "alice", "app", "x.lock"): "alice",
		filepath.Join("/", "home", "al", "x.lock"):           "al",
		filepath.Join("/", "home", "alex", "x.lock"):         "",
		filepath.Join("/", "srv", "x.lock"):                  "",
	} {
		if got := ownerHome(path, homes); got != want {
			t.Errorf("ownerHome(%q) = %q, want %q", path, got, want)
		}
	}
}
