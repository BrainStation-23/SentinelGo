package config

// Guard for token access: the agent has no -race CI job (it would need cgo),
// so token safety is enforced structurally instead. Outside this package,
// Config.AccessToken / Config.RefreshToken must only be touched through
// GetAccessToken / GetRefreshToken / SetTokens, which hold tokenMu.
//
// The check is type-aware (a grep would also flag unrelated fields such as a
// login response's AccessToken). It type-checks the module's own source for
// linux, darwin and windows and reports any field selection on config.Config's
// token fields. Third-party imports are replaced by empty stub packages, so
// nothing outside the module and the standard library is compiled and the test
// stays fast; the resulting type errors don't matter, because config.Config is
// always fully resolved. Composite literals that construct a Config are not
// flagged.

import (
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const (
	modulePath    = "sentinelgo"
	configPkgPath = "sentinelgo/internal/config"
)

func TestNoDirectTokenFieldAccess(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var offenders []string
	for _, goos := range []string{"linux", "darwin", "windows"} {
		found, err := tokenFieldAccesses(root, goos)
		if err != nil {
			t.Fatalf("GOOS=%s: %v", goos, err)
		}
		for _, f := range found {
			if !seen[f] {
				seen[f] = true
				offenders = append(offenders, f)
			}
		}
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Fatalf("direct access to config.Config token fields outside %s (use GetAccessToken/GetRefreshToken/SetTokens):\n  %s",
			configPkgPath, strings.Join(offenders, "\n  "))
	}
}

// moduleImporter type-checks module packages from source for one GOOS.
type moduleImporter struct {
	root     string
	ctx      build.Context
	fset     *token.FileSet
	std      types.Importer
	pkgs     map[string]*types.Package
	findings []string
}

// tokenFieldAccesses returns "file:line: expr" for every selection of
// Config.AccessToken/RefreshToken in non-test module code built for goos.
func tokenFieldAccesses(root, goos string) ([]string, error) {
	ctx := build.Default
	ctx.GOOS = goos
	ctx.GOARCH = "amd64"
	ctx.CgoEnabled = false
	fset := token.NewFileSet()
	im := &moduleImporter{
		root: root,
		ctx:  ctx,
		fset: fset,
		std:  importer.ForCompiler(fset, "source", nil),
		pkgs: map[string]*types.Package{},
	}

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return err
		}
		name := d.Name()
		if p != root && (strings.HasPrefix(name, ".") || name == "testdata" || name == "vendor" || name == "release") {
			return filepath.SkipDir
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		importPath := modulePath
		if rel != "." {
			importPath = path.Join(modulePath, filepath.ToSlash(rel))
		}
		_, err = im.Import(importPath)
		return err
	})
	return im.findings, err
}

func (im *moduleImporter) Import(importPath string) (*types.Package, error) {
	if p, ok := im.pkgs[importPath]; ok {
		return p, nil
	}
	if importPath == modulePath || strings.HasPrefix(importPath, modulePath+"/") {
		return im.checkModulePackage(importPath)
	}
	first, _, _ := strings.Cut(importPath, "/")
	if !strings.Contains(first, ".") && importPath != "C" {
		if p, err := im.std.Import(importPath); err == nil {
			im.pkgs[importPath] = p
			return p, nil
		}
	}
	// Third-party (or unresolvable): an empty stub keeps type-checking going.
	stub := types.NewPackage(importPath, path.Base(importPath))
	stub.MarkComplete()
	im.pkgs[importPath] = stub
	return stub, nil
}

func (im *moduleImporter) checkModulePackage(importPath string) (*types.Package, error) {
	dir := filepath.Join(im.root, filepath.FromSlash(strings.TrimPrefix(strings.TrimPrefix(importPath, modulePath), "/")))
	bp, err := im.ctx.ImportDir(dir, 0)
	if err != nil {
		var noGo *build.NoGoError
		if errors.As(err, &noGo) {
			// Directory with no Go files for this GOOS: nothing to check.
			p := types.NewPackage(importPath, path.Base(importPath))
			p.MarkComplete()
			im.pkgs[importPath] = p
			return p, nil
		}
		return nil, fmt.Errorf("import %s: %w", importPath, err)
	}

	var files []*ast.File
	for _, name := range bp.GoFiles {
		f, err := parser.ParseFile(im.fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}

	info := &types.Info{Selections: map[*ast.SelectorExpr]*types.Selection{}}
	conf := types.Config{Importer: im, Error: func(error) {}, FakeImportC: true}
	pkg, _ := conf.Check(importPath, im.fset, files, info) // type errors from stubs are expected
	im.pkgs[importPath] = pkg

	if importPath != configPkgPath {
		im.recordTokenSelections(info)
	}
	return pkg, nil
}

// recordTokenSelections appends every Config token-field selection in info.
func (im *moduleImporter) recordTokenSelections(info *types.Info) {
	for sel, s := range info.Selections {
		if s.Kind() != types.FieldVal || (sel.Sel.Name != "AccessToken" && sel.Sel.Name != "RefreshToken") {
			continue
		}
		if !isConfigType(s.Recv()) {
			continue
		}
		pos := im.fset.Position(sel.Pos())
		rel, _ := filepath.Rel(im.root, pos.Filename)
		im.findings = append(im.findings, fmt.Sprintf("%s:%d: %s", filepath.ToSlash(rel), pos.Line, types.ExprString(sel)))
	}
}

func isConfigType(t types.Type) bool {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	n, ok := t.(*types.Named)
	return ok && n.Obj().Name() == "Config" && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == configPkgPath
}
