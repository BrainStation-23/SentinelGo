package filescan

// Privacy guard (#341): file DLP reads employees' files, so this package must
// not log, print or write what it reads. The check is structural, like the
// token guard in internal/config: it parses this package's non-test sources
// and fails on any import of "log", any fmt print call, and any file access
// other than the spill file (os.CreateTemp / os.Remove), since the service
// opens files and hands them over (#328).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var forbiddenCalls = map[string]map[string]bool{
	"fmt": {"Print": true, "Printf": true, "Println": true, "Fprint": true, "Fprintf": true, "Fprintln": true},
	"os": {"Open": true, "OpenFile": true, "ReadFile": true, "WriteFile": true, "Create": true, "Stdout": true, "Stderr": true,
		"MkdirAll": true, "Mkdir": true, "Rename": true, "Link": true, "Symlink": true},
}

var forbiddenImports = map[string]bool{"log": true, "log/slog": true, "net": true, "net/http": true, "os/exec": true}

func TestNoContentLeaks(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var offenders []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name) // #nosec G304 -- this package's own sources
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		imported := map[string]string{} // local name -> path
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if forbiddenImports[p] {
				offenders = append(offenders, fset.Position(imp.Pos()).String()+": imports "+p)
			}
			local := filepath.Base(p)
			if imp.Name != nil {
				local = imp.Name.Name
			}
			imported[local] = p
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if forbiddenCalls[imported[id.Name]][sel.Sel.Name] {
				offenders = append(offenders, fset.Position(sel.Pos()).String()+": uses "+imported[id.Name]+"."+sel.Sel.Name)
			}
			return true
		})
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Fatalf("filescan must not log, print or touch files beyond its spill file (#341):\n  %s", strings.Join(offenders, "\n  "))
	}
}

// Results carry findings only: no field may hold extracted text.
func TestResultHasNoText(t *testing.T) {
	s := newTestScanner(t)
	secret := "TOPSECRET payload " + testCard + " the rest of the line"
	res := scanBytes(t, s, []byte(secret))
	dump := strings.Join([]string{res.Status, res.DetectedType, res.SHA256, strings.Join(res.Labels, ",")}, "|")
	for _, f := range res.Findings {
		dump += "|" + f.DetectorID + f.RuleID + f.Masked + f.SHA256
	}
	for _, leak := range []string{"payload", "the rest", testCard, "TOPSECRET"} {
		if strings.Contains(dump, leak) {
			t.Errorf("result contains %q: %s", leak, dump)
		}
	}
}
