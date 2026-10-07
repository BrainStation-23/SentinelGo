// licenses keeps third-party license obligations for the shipped agent binary
// visible and enforced.
//
// Modes (combinable):
//
//	go run ./scripts/licenses -check                            # fail if a dependency's license is not allow-listed
//	go run ./scripts/licenses -notices THIRD_PARTY_NOTICES.txt  # write attribution file to ship with binaries
//	go run ./scripts/licenses -sbom build/sbom                  # write one CycloneDX SBOM per release binary
//
// All modes walk every release GOOS/GOARCH, because the dependency set differs
// per platform (e.g. go-ole/wmi only on Windows, purego only on macOS). A
// Windows-only dev would otherwise never see a license pulled in by a Linux file.
//
// -check classifies licenses with github.com/google/go-licenses and -sbom uses
// github.com/CycloneDX/cyclonedx-gomod, both at pinned versions. Each tool is
// installed into a temp dir for the host and then run with the target
// GOOS/GOARCH; `go run pkg@version` can't be used directly because it would
// build the tool itself for the target OS. Nothing is added to go.mod.
//
// -notices needs no classifier: it copies every license/notice file found in
// each module's root (LICENSE*, COPYING*, NOTICE*, PATENTS) verbatim, which is
// what BSD/MIT/Apache require for binary redistribution.
//
// It is a plain Go program rather than a shell loop so `make license-check` and
// `make notices` work the same on Windows, macOS and Linux dev machines.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

const (
	goLicensesPkg     = "github.com/google/go-licenses/v2@v2.0.1"
	cyclonedxGomodPkg = "github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.12.0"
)

// mainPkg is the binary we ship. Notices describe exactly what is linked into it.
const mainPkg = "./cmd/sentinelgo"

// checkPkgs covers every entrypoint so a bad license can't sneak in via a
// secondary binary either.
const checkPkgs = "./cmd/..."

// targets mirrors the release matrix in the Makefile (`make all`).
var targets = [][2]string{
	{"linux", "amd64"},
	{"linux", "arm64"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
	{"windows", "amd64"},
}

// allowedLicenses are permissive licenses compatible with shipping a closed
// static binary under Apache-2.0. Anything else (GPL/LGPL/AGPL, unknown) fails
// the check and needs a deliberate decision.
var allowedLicenses = []string{
	"Apache-2.0",
	"BSD-2-Clause",
	"BSD-3-Clause",
	"ISC",
	"MIT",
	"MPL-2.0",
}

// exceptions are modules whose license can't be detected but which have been
// reviewed. Each entry must say why; remove it as soon as upstream is fixed.
var exceptions = map[string]string{
	// Transitive via supabase-go (we only use its gotrue RefreshToken). The
	// upstream repo has no LICENSE file in any tagged version (checked v0.8.1,
	// 2026-10). Tracked as a known gap; the clean fix is to drop supabase-go in
	// favour of gotrue-go directly so storage-go is no longer linked.
	"github.com/supabase-community/storage-go": "no upstream license file; transitive via supabase-go",
}

func main() {
	check := flag.Bool("check", false, "fail if any dependency license is not in the allow-list")
	notices := flag.String("notices", "", "write third-party notices for "+mainPkg+" to this file")
	sbom := flag.String("sbom", "", "write a CycloneDX SBOM per release binary into this directory")
	flag.Parse()

	if !*check && *notices == "" && *sbom == "" {
		fmt.Fprintln(os.Stderr, "usage: licenses [-check] [-notices <file>] [-sbom <dir>]")
		os.Exit(2)
	}
	if *check {
		if err := runCheck(); err != nil {
			fmt.Fprintln(os.Stderr, "license check failed:", err)
			os.Exit(1)
		}
	}
	if *notices != "" {
		if err := writeNotices(*notices); err != nil {
			fmt.Fprintln(os.Stderr, "writing notices failed:", err)
			os.Exit(1)
		}
	}
	if *sbom != "" {
		if err := writeSBOMs(*sbom); err != nil {
			fmt.Fprintln(os.Stderr, "writing SBOMs failed:", err)
			os.Exit(1)
		}
	}
}

func runCheck() error {
	bin, cleanup, err := installTool(goLicensesPkg)
	if err != nil {
		return err
	}
	defer cleanup()

	args := []string{"check", checkPkgs, "--allowed_licenses=" + strings.Join(allowedLicenses, ",")}
	for mod := range exceptions {
		args = append(args, "--ignore="+mod)
	}

	for _, t := range targets {
		fmt.Printf("checking licenses for %s/%s ...\n", t[0], t[1])
		cmd := exec.Command(bin, args...)
		cmd.Env = targetEnv(t)
		cmd.Stdout = os.Stdout
		// go-licenses logs every non-Go file it skips (assembly etc.) at
		// warning level; keep stderr for real errors only.
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			printErrors(stderr.String())
			return fmt.Errorf("%s/%s: %w", t[0], t[1], err)
		}
	}
	fmt.Println("ok: all dependency licenses are allow-listed")
	for mod, why := range exceptions {
		fmt.Printf("  exception: %s (%s)\n", mod, why)
	}
	return nil
}

// writeSBOMs writes <dir>/<release binary name>.cdx.json for every target.
func writeSBOMs(dir string) error {
	bin, cleanup, err := installTool(cyclonedxGomodPkg)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, t := range targets {
		name := "sentinelgo-" + t[0] + "-" + t[1]
		if t[0] == "windows" {
			name += ".exe"
		}
		out := filepath.Join(dir, name+".cdx.json")
		cmd := exec.Command(bin, "app", "-json", "-licenses", "-main", mainPkg, "-output", out, ".")
		cmd.Env = targetEnv(t)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		fmt.Println("wrote", out)
	}
	return nil
}

// installTool builds a pinned Go tool (pkg@version) for the host into a temp
// dir and returns the executable path plus a cleanup func.
func installTool(pkg string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "sentinelgo-tool-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }

	cmd := exec.Command("go", "install", pkg)
	cmd.Env = append(hostEnv(), "GOBIN="+dir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("installing %s: %w", pkg, err)
	}
	// go install names the binary after the last path element, skipping a
	// major-version suffix (".../go-licenses/v2" installs "go-licenses").
	elems := strings.Split(strings.SplitN(pkg, "@", 2)[0], "/")
	name := elems[len(elems)-1]
	if len(elems) > 1 && len(name) > 1 && name[0] == 'v' && strings.Trim(name[1:], "0123456789") == "" {
		name = elems[len(elems)-2]
	}
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(dir, name), cleanup, nil
}

// printErrors forwards go-licenses' stderr minus its "W..." warnings about
// non-Go files (and the assembly/header paths those warnings list).
func printErrors(s string) {
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := sc.Text()
		ext := filepath.Ext(line)
		if strings.HasPrefix(line, "W") || ext == ".s" || ext == ".h" || ext == ".c" {
			continue
		}
		fmt.Fprintln(os.Stderr, line)
	}
}

// module is one dependency linked into the shipped binary.
type module struct {
	Path, Version, Dir string
	Platforms          []string
}

func writeNotices(out string) error {
	mods := map[string]*module{}
	for _, t := range targets {
		if err := collectModules(t, mods); err != nil {
			return err
		}
	}

	paths := make([]string, 0, len(mods))
	for p := range mods {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	text, err := renderNotices(paths, mods)
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, []byte(text), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d modules)\n", out, len(paths))
	return nil
}

// collectModules adds every non-main module linked into mainPkg for target t.
func collectModules(t [2]string, mods map[string]*module) error {
	cmd := exec.Command("go", "list", "-deps",
		"-f", "{{with .Module}}{{if not .Main}}{{.Path}}\t{{.Version}}\t{{.Dir}}{{end}}{{end}}",
		mainPkg)
	cmd.Env = targetEnv(t)
	cmd.Stderr = os.Stderr
	raw, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("go list for %s/%s: %w", t[0], t[1], err)
	}
	platform := t[0] + "/" + t[1]
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Split(strings.TrimSpace(line), "\t")
		if len(f) != 3 {
			continue
		}
		m, ok := mods[f[0]]
		if !ok {
			m = &module{Path: f[0], Version: f[1], Dir: f[2]}
			mods[f[0]] = m
		}
		// go list prints one line per package, so a module repeats.
		if n := len(m.Platforms); n == 0 || m.Platforms[n-1] != platform {
			m.Platforms = append(m.Platforms, platform)
		}
	}
	return nil
}

// renderNotices builds the notices file: an index, then each module's license
// and notice files verbatim.
func renderNotices(paths []string, mods map[string]*module) (string, error) {
	var b strings.Builder
	b.WriteString("SentinelGo - Third-Party Notices\n")
	b.WriteString("================================\n\n")
	b.WriteString("SentinelGo is licensed under the Apache License 2.0 (see LICENSE).\n")
	b.WriteString("The SentinelGo binaries include the following third-party Go modules.\n")
	b.WriteString("Their license and notice files are reproduced below as required.\n")
	b.WriteString("Generated by `make notices`; do not edit by hand.\n\n")
	for _, p := range paths {
		fmt.Fprintf(&b, "  %s %s\n", p, mods[p].Version)
	}

	for _, p := range paths {
		if err := renderModule(&b, mods[p]); err != nil {
			return "", fmt.Errorf("%s: %w", p, err)
		}
	}
	return b.String(), nil
}

// renderModule writes one module's header and its license/notice files.
func renderModule(b *strings.Builder, m *module) error {
	files, err := licenseFiles(m.Dir)
	if err != nil {
		return err
	}
	b.WriteString("\n" + strings.Repeat("=", 78) + "\n")
	fmt.Fprintf(b, "%s %s\n", m.Path, m.Version)
	if len(m.Platforms) < len(targets) {
		fmt.Fprintf(b, "Included on: %s\n", strings.Join(m.Platforms, ", "))
	}
	b.WriteString(strings.Repeat("=", 78) + "\n")
	if len(files) == 0 {
		b.WriteString("\nNo license file is published in this module's source.\n")
		return nil
	}
	for _, f := range files {
		text, err := os.ReadFile(filepath.Join(m.Dir, f))
		if err != nil {
			return err
		}
		fmt.Fprintf(b, "\n--- %s ---\n\n", f)
		b.Write(bytes.TrimRight(text, "\r\n\t "))
		b.WriteString("\n")
	}
	return nil
}

// licenseFiles returns the license/notice files in a module root, sorted.
func licenseFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToUpper(e.Name())
		for _, prefix := range []string{"LICENSE", "LICENCE", "COPYING", "NOTICE", "PATENTS"} {
			if strings.HasPrefix(name, prefix) {
				files = append(files, e.Name())
				break
			}
		}
	}
	sort.Strings(files)
	return files, nil
}

// targetEnv is the environment for analysing one release target.
func targetEnv(t [2]string) []string {
	return append(hostEnv(), "GOOS="+t[0], "GOARCH="+t[1], "CGO_ENABLED=0")
}

// hostEnv is os.Environ without any GOOS/GOARCH the caller may have set, so
// tools are built for (and runnable on) the host.
func hostEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "GOOS=") || strings.HasPrefix(kv, "GOARCH=") {
			continue
		}
		env = append(env, kv)
	}
	return env
}
