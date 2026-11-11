package engine

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestOnlyEngineImportsGoYara keeps go-yara behind this package: no other
// package (tests included) imports it, so the engine stays replaceable.
func TestOnlyEngineImportsGoYara(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	self, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var offenders []string
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "release", "bin", "node_modules", "testdata":
				return filepath.SkipDir
			}
			// tools/ has its own modules.
			if p != root && fileExists(filepath.Join(p, "go.mod")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || filepath.Dir(p) == self {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			if path == goYaraModule || strings.HasPrefix(path, goYaraModule+"/") {
				rel, _ := filepath.Rel(root, p)
				offenders = append(offenders, rel)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Fatalf("go-yara imported outside internal/yara/engine:\n  %s", strings.Join(offenders, "\n  "))
	}
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// TestPinnedVersionMatchesGoMod: go.mod pins go-yara exactly, to the version
// pinnedVersion names (the engine_version fallback).
func TestPinnedVersionMatchesGoMod(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(goYaraModule) + `\s+(\S+)`).FindSubmatch(data)
	if m == nil {
		t.Fatal("go-yara not in go.mod")
	}
	if string(m[1]) != pinnedVersion {
		t.Fatalf("go.mod has go-yara %s, pinnedVersion is %s: update both together after reviewing the changelog", m[1], pinnedVersion)
	}
}
