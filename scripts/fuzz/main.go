// fuzz discovers and runs the repository's Go fuzz targets (func FuzzXxx(*testing.F)).
//
// `go test -fuzz` accepts only one target per package per invocation, so this
// tool loops over every target. Discovery is static (go/build + go/parser), so
// targets can be listed for any GOOS from any host, which lets one CI job emit
// the matrix for all three runners.
//
// Usage:
//
//	go run ./scripts/fuzz [-fuzztime=30s] [-run=<regexp>]  # fuzz every host-OS target in turn
//	go run ./scripts/fuzz -list                             # print "<package> <target>" for the host OS
//	go run ./scripts/fuzz -matrix                           # print the CI matrix (JSON) for all OSes
//
// It is a plain Go program rather than a shell loop so `make fuzz` works the
// same on Windows, macOS and Linux dev machines.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// runnerFor maps a GOOS to the GitHub-hosted runner that can execute it.
var runnerFor = map[string]string{
	"linux":   "ubuntu-latest",
	"darwin":  "macos-latest",
	"windows": "windows-latest",
}

// target is one fuzz function and the package that holds it.
type target struct {
	Pkg    string `json:"pkg"`    // ./-relative package path, e.g. ./internal/updater
	Dir    string `json:"dir"`    // slash-separated directory, e.g. internal/updater
	Target string `json:"target"` // e.g. FuzzParseSemver
	OS     string `json:"os"`     // GOOS the matrix entry runs on
	Runner string `json:"runner"` // GitHub runner label
}

func main() {
	fuzztime := flag.String("fuzztime", "30s", "time to fuzz each target (passed to go test -fuzztime)")
	runFilter := flag.String("run", "", "only fuzz targets whose name matches this regexp")
	list := flag.Bool("list", false, "list host-OS targets instead of fuzzing them")
	matrix := flag.Bool("matrix", false, "print the CI matrix as JSON for linux, darwin and windows")
	flag.Parse()

	if *matrix {
		printMatrix()
		return
	}

	targets, err := discover(runtime.GOOS)
	if err != nil {
		fail("discover fuzz targets: %v", err)
	}
	if *runFilter != "" {
		re, err := regexp.Compile(*runFilter)
		if err != nil {
			fail("invalid -run regexp: %v", err)
		}
		targets = filter(targets, re)
	}

	if *list {
		for _, t := range targets {
			fmt.Printf("%s %s\n", t.Pkg, t.Target)
		}
		return
	}
	if len(targets) == 0 {
		fail("no fuzz targets found for GOOS=%s", runtime.GOOS)
	}
	for i, t := range targets {
		fmt.Printf("==> [%d/%d] %s %s (fuzztime %s)\n", i+1, len(targets), t.Pkg, t.Target, *fuzztime)
		if err := runTarget(t, *fuzztime); err != nil {
			fmt.Fprintf(os.Stderr, "\n%s failed: %v\n", t.Target, err)
			fmt.Fprintf(os.Stderr, "The failing input was written under %s/testdata/fuzz/%s/.\n", t.Dir, t.Target)
			fmt.Fprintf(os.Stderr, "Reproduce with: go test -run='^%s$/<file name>' %s\n", t.Target, t.Pkg)
			os.Exit(1)
		}
	}
	fmt.Printf("all %d fuzz targets passed\n", len(targets))
}

// runTarget fuzzes a single target, streaming go test's output.
func runTarget(t target, fuzztime string) error {
	// #nosec G204 - arguments are fuzz target names discovered from this repo's own source
	cmd := exec.Command("go", "test", "-run=^$", "-fuzz=^"+t.Target+"$", "-fuzztime="+fuzztime, t.Pkg)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	return cmd.Run()
}

// printMatrix emits one entry per (target, OS). A target whose file builds on
// every OS runs on Linux only (the cheapest runner); an OS-specific file runs
// on each OS it builds for, preferring Linux when Linux is among them.
func printMatrix() {
	seen := map[string]bool{}
	byKey := map[string]map[string]bool{} // pkg+target -> set of GOOS it builds on
	var all []target
	for _, goos := range []string{"linux", "darwin", "windows"} {
		ts, err := discover(goos)
		if err != nil {
			fail("discover fuzz targets for %s: %v", goos, err)
		}
		for _, t := range ts {
			key := t.Pkg + " " + t.Target
			if byKey[key] == nil {
				byKey[key] = map[string]bool{}
			}
			byKey[key][goos] = true
			if !seen[key] {
				seen[key] = true
				all = append(all, t)
			}
		}
	}

	var out []target
	for _, t := range all {
		oses := byKey[t.Pkg+" "+t.Target]
		goos := "linux"
		if !oses["linux"] {
			goos = "darwin"
			if !oses["darwin"] {
				goos = "windows"
			}
		}
		t.OS, t.Runner = goos, runnerFor[goos]
		out = append(out, t)
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fail("encode matrix: %v", err)
	}
}

// discover finds every FuzzXxx(*testing.F) in _test.go files that build for goos.
func discover(goos string) ([]target, error) {
	ctx := build.Default
	ctx.GOOS = goos
	ctx.CgoEnabled = false

	var targets []target
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != "." && (strings.HasPrefix(name, ".") || name == "testdata" || name == "vendor" || name == "release") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		dir, file := filepath.Split(path)
		dir = filepath.Clean(dir)
		if ok, err := ctx.MatchFile(dir, file); err != nil || !ok {
			return err
		}
		names, err := fuzzFuncs(path)
		if err != nil {
			return err
		}
		slashDir := filepath.ToSlash(dir)
		for _, n := range names {
			targets = append(targets, target{Pkg: "./" + slashDir, Dir: slashDir, Target: n})
		}
		return nil
	})
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Pkg != targets[j].Pkg {
			return targets[i].Pkg < targets[j].Pkg
		}
		return targets[i].Target < targets[j].Target
	})
	return targets, err
}

// fuzzFuncs returns the names of top-level FuzzXxx(f *testing.F) functions in a file.
func fuzzFuncs(path string) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || !strings.HasPrefix(fn.Name.Name, "Fuzz") {
			continue
		}
		if params := fn.Type.Params.List; len(params) == 1 && isTestingF(params[0].Type) {
			names = append(names, fn.Name.Name)
		}
	}
	return names, nil
}

// isTestingF reports whether expr is *testing.F.
func isTestingF(expr ast.Expr) bool {
	star, ok := expr.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "testing" && sel.Sel.Name == "F"
}

func filter(ts []target, re *regexp.Regexp) []target {
	var out []target
	for _, t := range ts {
		if re.MatchString(t.Target) {
			out = append(out, t)
		}
	}
	return out
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "fuzz: "+format+"\n", args...)
	os.Exit(1)
}
