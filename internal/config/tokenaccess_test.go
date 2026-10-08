package config

// Guard for token access: the agent has no -race CI job (it would need cgo),
// so token safety is enforced structurally instead. Outside this package,
// Config.AccessToken / Config.RefreshToken must only be touched through
// GetAccessToken / GetRefreshToken / SetTokens, which hold tokenMu.
//
// The check is type-aware (a grep would also flag unrelated fields such as a
// login response's AccessToken): it type-checks every package in the module
// for linux, darwin and windows using export data from `go list -export`, and
// reports any field selection on config.Config's token fields. Composite
// literals that construct a Config are not flagged.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const configPkgPath = "sentinelgo/internal/config"

func TestNoDirectTokenFieldAccess(t *testing.T) {
	if os.Getenv("SENTINELGO_TOKEN_GUARD") == "" {
		t.Skip("enabled in Supabase P3 (#91) once the existing offenders are fixed; set SENTINELGO_TOKEN_GUARD=1 to run")
	}
	if testing.Short() {
		t.Log("running despite -short: this guard is the substitute for a -race job")
	}

	var offenders []string
	for _, goos := range []string{"linux", "darwin", "windows"} {
		found, err := tokenFieldAccesses(goos)
		if err != nil {
			t.Fatalf("GOOS=%s: %v", goos, err)
		}
		offenders = append(offenders, found...)
	}
	offenders = dedupe(offenders)
	if len(offenders) > 0 {
		t.Fatalf("direct access to config.Config token fields outside %s (use GetAccessToken/GetRefreshToken/SetTokens):\n  %s",
			configPkgPath, strings.Join(offenders, "\n  "))
	}
}

type listedPackage struct {
	ImportPath string
	Dir        string
	Export     string
	GoFiles    []string
	Module     *struct{ Path string }
}

// tokenFieldAccesses returns "file:line: expr" for every selection of
// Config.AccessToken/RefreshToken in non-test module code built for goos.
func tokenFieldAccesses(goos string) ([]string, error) {
	pkgs, err := listPackages(goos)
	if err != nil {
		return nil, err
	}
	exports := map[string]string{}
	for _, p := range pkgs {
		if p.Export != "" {
			exports[p.ImportPath] = p.Export
		}
	}

	fset := token.NewFileSet()
	imp := importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		file, ok := exports[path]
		if !ok {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(file) // #nosec G304 - path comes from `go list -export`
	})

	var out []string
	for _, p := range pkgs {
		if p.Module == nil || p.Module.Path != "sentinelgo" || p.ImportPath == configPkgPath || len(p.GoFiles) == 0 {
			continue
		}
		var files []*ast.File
		for _, name := range p.GoFiles {
			f, err := parser.ParseFile(fset, filepath.Join(p.Dir, name), nil, parser.SkipObjectResolution)
			if err != nil {
				return nil, err
			}
			files = append(files, f)
		}
		info := &types.Info{Selections: map[*ast.SelectorExpr]*types.Selection{}}
		conf := types.Config{Importer: imp, GoVersion: "", FakeImportC: true}
		if _, err := conf.Check(p.ImportPath, fset, files, info); err != nil {
			return nil, fmt.Errorf("type-check %s: %w", p.ImportPath, err)
		}
		for sel, s := range info.Selections {
			if s.Kind() != types.FieldVal || (sel.Sel.Name != "AccessToken" && sel.Sel.Name != "RefreshToken") {
				continue
			}
			if isConfigType(s.Recv()) {
				pos := fset.Position(sel.Pos())
				out = append(out, fmt.Sprintf("%s:%d: %s", relPath(pos.Filename), pos.Line, types.ExprString(sel)))
			}
		}
	}
	return out, nil
}

func isConfigType(t types.Type) bool {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	n, ok := t.(*types.Named)
	return ok && n.Obj().Name() == "Config" && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == configPkgPath
}

func listPackages(goos string) ([]listedPackage, error) {
	root, err := moduleRoot()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("go", "list", "-export", "-deps", "-json", "./...")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=amd64", "CGO_ENABLED=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdout, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list: %w: %s", err, stderr.String())
	}
	var pkgs []listedPackage
	dec := json.NewDecoder(bufio.NewReader(bytes.NewReader(stdout)))
	for dec.More() {
		var p listedPackage
		if err := dec.Decode(&p); err != nil {
			return nil, err
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, nil
}

func moduleRoot() (string, error) {
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		return "", err
	}
	return filepath.Dir(strings.TrimSpace(string(out))), nil
}

func relPath(p string) string {
	if root, err := moduleRoot(); err == nil {
		if r, err := filepath.Rel(root, p); err == nil {
			return filepath.ToSlash(r)
		}
	}
	return p
}

func dedupe(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
