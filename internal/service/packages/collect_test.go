package packages

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// pinRoots points the collector at a temp tree: one system root of each kind
// under sys/, and the per-user roots of the test under each home.
func pinRoots(t *testing.T, sys string, homes []string, hr []homeRoot) {
	t.Helper()
	origSys, origHome, origHomes := systemRootsFn, homeRootsFn, userHomeDirs
	t.Cleanup(func() { systemRootsFn, homeRootsFn, userHomeDirs = origSys, origHome, origHomes })
	systemRootsFn = func() []root {
		return []root{
			{kindNodeModules, filepath.Join(sys, "lib", "node_modules")},
			{kindSitePackages, filepath.Join(sys, "lib", "python3*", "site-packages")},
		}
	}
	homeRootsFn = func() []homeRoot { return hr }
	userHomeDirs = func() []string { return homes }
}

func TestCollectGlobal(t *testing.T) {
	dir := t.TempDir()
	sys := filepath.Join(dir, "sys")
	alice := filepath.Join(dir, "home", "alice")

	nm := filepath.Join(sys, "lib", "node_modules")
	write(t, filepath.Join(nm, "npm", "package.json"), `{"name":"npm","version":"10.8.2"}`)
	write(t, filepath.Join(nm, "@tanstack", "query-core", "package.json"), `{"name":"@tanstack/query-core","version":"5.59.0"}`)
	write(t, filepath.Join(nm, ".bin", "package.json"), `{"name":"bin","version":"1"}`)
	write(t, filepath.Join(nm, "broken", "package.json"), `{not json`)
	write(t, filepath.Join(nm, "npm", "node_modules", "nested", "package.json"), `{"name":"nested","version":"1"}`)

	sp := filepath.Join(sys, "lib", "python3.12", "site-packages")
	write(t, filepath.Join(sp, "requests-2.32.3.dist-info", "METADATA"), "Name: requests\nVersion: 2.32.3\n")
	write(t, filepath.Join(sp, "old-1.0.egg-info", "PKG-INFO"), "Name: old\nVersion: 1.0\n")
	write(t, filepath.Join(sp, "flat-2.0.egg-info"), "Name: flat\nVersion: 2.0\n")
	write(t, filepath.Join(sp, "requests", "__init__.py"), "")

	write(t, filepath.Join(alice, ".composer", "vendor", "composer", "installed.json"),
		`{"packages":[{"name":"laravel/installer","version":"v5.8.3"}]}`)
	write(t, filepath.Join(alice, ".nvm", "versions", "node", "v20.1.0", "lib", "node_modules", "keyv", "package.json"),
		`{"name":"keyv","version":"4.5.4"}`)

	pinRoots(t, sys, []string{alice}, []homeRoot{
		{kindComposerHome, ".composer"},
		{kindNodeModules, filepath.Join(".nvm", "versions", "node", "*", "lib", "node_modules")},
		{kindSitePackages, filepath.Join(".local", "lib", "python*", "site-packages")}, // missing: fine
	})

	pkgs, complete := CollectGlobal(context.Background())
	if !complete {
		t.Error("complete = false, want true")
	}
	got := map[string]Package{}
	for _, p := range pkgs {
		got[p.Ecosystem+":"+p.Name+"@"+p.Version] = p
	}
	want := []string{
		"npm:npm@10.8.2", "npm:@tanstack/query-core@5.59.0", "npm:keyv@4.5.4",
		"pypi:requests@2.32.3", "pypi:old@1.0", "pypi:flat@2.0",
		"packagist:laravel/installer@5.8.3",
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("missing %s; got %v", k, keys(got))
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d packages, want %d: %v", len(got), len(want), keys(got))
	}

	if p := got["npm:keyv@4.5.4"]; p.User != "alice" || p.Scope != ScopeGlobal ||
		p.Location != filepath.Join(alice, ".nvm", "versions", "node", "v20.1.0", "lib", "node_modules", "keyv") {
		t.Errorf("keyv = %+v", p)
	}
	if p := got["npm:npm@10.8.2"]; p.User != "" {
		t.Errorf("system package has user %q", p.User)
	}
	if p := got["packagist:laravel/installer@5.8.3"]; p.Location != filepath.Join(alice, ".composer", "vendor", "laravel", "installer") {
		t.Errorf("composer location = %q", p.Location)
	}
	if p := got["pypi:requests@2.32.3"]; p.Location != filepath.Join(sp, "requests-2.32.3.dist-info") {
		t.Errorf("pypi location = %q", p.Location)
	}
}

func TestCollectGlobal_SkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	sys := filepath.Join(dir, "sys")
	nm := filepath.Join(sys, "lib", "node_modules")
	project := filepath.Join(dir, "project")
	write(t, filepath.Join(project, "package.json"), `{"name":"linked","version":"0.0.1"}`)
	if err := os.MkdirAll(nm, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(project, filepath.Join(nm, "linked")); err != nil {
		t.Skipf("symlinks not available: %v", err)
	}
	pinRoots(t, sys, nil, nil)

	pkgs, complete := CollectGlobal(context.Background())
	if len(pkgs) != 0 || !complete {
		t.Errorf("CollectGlobal = %+v, %v; want nothing, complete", pkgs, complete)
	}
}

func TestCollectGlobal_CancelledIsIncomplete(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "sys", "lib", "node_modules", "a", "package.json"), `{"name":"a","version":"1"}`)
	pinRoots(t, filepath.Join(dir, "sys"), nil, nil)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, complete := CollectGlobal(ctx); complete {
		t.Error("a cancelled run reported complete")
	}
}

func TestReadLimited_TooLarge(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big")
	write(t, p, "0123456789")
	if _, err := readLimited(p, 5); err != errTooLarge {
		t.Errorf("err = %v, want errTooLarge", err)
	}
	if b, err := readLimited(p, 10); err != nil || len(b) != 10 {
		t.Errorf("readLimited at the limit = %d bytes, %v", len(b), err)
	}
}

func keys(m map[string]Package) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
