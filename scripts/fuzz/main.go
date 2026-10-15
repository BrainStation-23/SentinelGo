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
//	go run ./scripts/fuzz -targets='<pkg>:<Target> ...'     # fuzz exactly these targets (CI shards)
//	go run ./scripts/fuzz -list                             # print "<package> <target>" for the host OS
//	go run ./scripts/fuzz -matrix [-shard-size=9]           # print the CI matrix (JSON) for all OSes
//
// Every target is fuzzed even after one fails, so a single run reports every
// failing target; the exit status is non-zero if any failed.
//
// It is a plain Go program rather than a shell loop so `make fuzz` works the
// same on Windows, macOS and Linux dev machines.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io"
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

// shard is one CI job: a group of targets fuzzed one after another on one
// runner, so a nightly run starts a few jobs rather than one per target.
type shard struct {
	Name   string `json:"name"`   // e.g. linux-2
	OS     string `json:"os"`     // GOOS the targets build for
	Runner string `json:"runner"` // GitHub runner label
	// Targets lists the shard's targets as space-separated "<pkg>:<Target>"
	// pairs for -targets. The package is part of each entry because Go allows
	// two packages to define fuzz targets with the same name.
	Targets string `json:"targets"`
	Count   int    `json:"count"` // number of targets
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
	only := flag.String("targets", "", `only fuzz these targets: space- or comma-separated "<pkg>:<Target>" pairs`)
	list := flag.Bool("list", false, "list host-OS targets instead of fuzzing them")
	matrix := flag.Bool("matrix", false, "print the CI matrix as JSON for linux, darwin and windows")
	shardSize := flag.Int("shard-size", 9, "with -matrix: the most targets one CI job fuzzes")
	flag.Parse()

	if *matrix {
		if *shardSize < 1 {
			fail("-shard-size must be at least 1")
		}
		printMatrix(*shardSize)
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
	if *only != "" {
		targets, err = selectTargets(targets, *only)
		if err != nil {
			fail("%v", err)
		}
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
	var failed []target
	for i, t := range targets {
		fmt.Printf("==> [%d/%d] %s %s (fuzztime %s)\n", i+1, len(targets), t.Pkg, t.Target, *fuzztime)
		if err := runTarget(t, *fuzztime); err != nil {
			fmt.Fprintf(os.Stderr, "\n%s failed: %v\n", t.Target, err)
			failed = append(failed, t)
		}
	}
	if len(failed) == 0 {
		fmt.Printf("all %d fuzz targets passed\n", len(targets))
		return
	}
	fmt.Fprintf(os.Stderr, "\n%d of %d fuzz targets failed:\n", len(failed), len(targets))
	for _, t := range failed {
		fmt.Fprintf(os.Stderr, "- %s: failing input under %s/testdata/fuzz/%s/\n", t.Target, t.Dir, t.Target)
		fmt.Fprintf(os.Stderr, "  reproduce with: go test -run='^%s$/<file name>' %s\n", t.Target, t.Pkg)
	}
	os.Exit(1)
}

// runTarget fuzzes a single target, streaming go test's output.
//
// The Go fuzzer can end with "context deadline exceeded" when -fuzztime runs
// out while a slow input is still executing. That is not a finding (a real
// failure always prints "Failing input written to ..."), so it is reported as
// a warning instead of an error.
func runTarget(t target, fuzztime string) error {
	var out bytes.Buffer
	// #nosec G204 - arguments are fuzz target names discovered from this repo's own source
	cmd := exec.Command("go", "test", "-run=^$", "-fuzz=^"+t.Target+"$", "-fuzztime="+fuzztime, t.Pkg)
	cmd.Stdout = io.MultiWriter(os.Stdout, &out)
	cmd.Stderr = io.MultiWriter(os.Stderr, &out)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	err := cmd.Run()
	if err != nil && isDeadlineOnly(out.String()) {
		fmt.Fprintf(os.Stderr, "warning: %s hit its deadline mid-input without a failing input; treating as a pass\n", t.Target)
		return nil
	}
	return err
}

// isDeadlineOnly reports whether go test output shows the fuzzer's deadline
// quirk rather than an actual failing input.
func isDeadlineOnly(output string) bool {
	return strings.Contains(output, "context deadline exceeded") &&
		!strings.Contains(output, "Failing input written to")
}

// printMatrix emits the CI jobs: each target is assigned one OS, then each
// OS's targets are split into shards of at most shardSize. A target whose file
// builds on every OS runs on Linux only (the cheapest runner); an OS-specific
// file runs on one OS it builds for, preferring Linux, then macOS.
func printMatrix(shardSize int) {
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

	byOS := map[string][]target{}
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
		byOS[goos] = append(byOS[goos], t)
	}
	out := []shard{}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		out = append(out, shards(byOS[goos], shardSize)...)
	}
	if err := json.NewEncoder(os.Stdout).Encode(out); err != nil {
		fail("encode matrix: %v", err)
	}
}

// shards splits one OS's targets into near-equal groups of at most size.
func shards(ts []target, size int) []shard {
	if len(ts) == 0 {
		return nil
	}
	n := (len(ts) + size - 1) / size
	out := make([]shard, 0, n)
	for i := 0; i < n; i++ {
		group := ts[i*len(ts)/n : (i+1)*len(ts)/n]
		pairs := make([]string, len(group))
		for j, t := range group {
			pairs[j] = t.Pkg + ":" + t.Target
		}
		out = append(out, shard{
			Name:    fmt.Sprintf("%s-%d", group[0].OS, i+1),
			OS:      group[0].OS,
			Runner:  group[0].Runner,
			Targets: strings.Join(pairs, " "),
			Count:   len(group),
		})
	}
	return out
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

// selectTargets keeps the targets named by spec, a list of "<pkg>:<Target>"
// pairs. It fails if a pair names a target that doesn't build on this OS, so a
// shard can never silently fuzz less than it was given.
func selectTargets(ts []target, spec string) ([]target, error) {
	want := map[string]bool{}
	for _, pair := range strings.FieldsFunc(spec, func(r rune) bool { return r == ' ' || r == ',' }) {
		want[pair] = true
	}
	var out []target
	for _, t := range ts {
		key := t.Pkg + ":" + t.Target
		if want[key] {
			out = append(out, t)
			delete(want, key)
		}
	}
	if len(want) > 0 {
		missing := make([]string, 0, len(want))
		for k := range want {
			missing = append(missing, k)
		}
		sort.Strings(missing)
		return nil, fmt.Errorf("no such fuzz target for GOOS=%s: %s", runtime.GOOS, strings.Join(missing, ", "))
	}
	return out, nil
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
