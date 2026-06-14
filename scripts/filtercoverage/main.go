// filtercoverage rewrites coverage.out to exclude files listed in
// sonar.coverage.exclusions, producing coverage-filtered.out, then runs
// "go tool cover -func=coverage-filtered.out".
//
// Usage: go run ./scripts/filtercoverage [coverage.out]
//
// sonar-project.properties is read from the working directory (repo root).
// coverage-filtered.out is also written to the working directory.
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	module   = "sentinelgo"
	propsFile = "sonar-project.properties"
	filtered  = "coverage-filtered.out"
)

func main() {
	profile := "coverage.out"
	if len(os.Args) > 1 {
		profile = os.Args[1]
	}

	excludes, err := parseExclusions(propsFile)
	if err != nil {
		fatalf("parse %s: %v", propsFile, err)
	}

	if err := writeFiltered(profile, filtered, excludes); err != nil {
		fatalf("write %s: %v", filtered, err)
	}

	cmd := exec.Command("go", "tool", "cover", "-func="+filtered)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		os.Exit(1)
	}
}

// parseExclusions reads sonar.coverage.exclusions from sonar-project.properties
// and returns a set of fully-qualified Go coverage profile paths
// (e.g. "sentinelgo/internal/config/secure_windows.go").
func parseExclusions(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	set := make(map[string]bool)
	inBlock := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "sonar.coverage.exclusions=") {
			inBlock = true
		}

		if inBlock {
			// Each continuation line: "  internal/config/secure_windows.go,\"
			trimmed := strings.TrimSpace(line)
			trimmed = strings.TrimSuffix(trimmed, `\`)
			trimmed = strings.TrimSuffix(trimmed, ",")
			trimmed = strings.TrimSpace(trimmed)

			if strings.HasSuffix(trimmed, ".go") && !strings.Contains(trimmed, "=") {
				set[module+"/"+trimmed] = true
			}

			// Block ends when the line has no trailing backslash.
			if !strings.HasSuffix(strings.TrimSpace(line), `\`) {
				inBlock = false
			}
		}
	}

	return set, scanner.Err()
}

// writeFiltered writes a new coverage profile that omits lines for excluded files.
func writeFiltered(src, dst string, excludes map[string]bool) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w (run 'go test -coverprofile=%s ./...' first)", src, err, src)
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	defer out.Close()

	w := bufio.NewWriter(out)
	scanner := bufio.NewScanner(in)
	first := true

	for scanner.Scan() {
		line := scanner.Text()

		if first {
			// "mode: set" header — always keep
			fmt.Fprintln(w, line)
			first = false
			continue
		}

		// Profile line format: "pkg/path/file.go:L.C,L.C N N"
		// File path is everything before the first colon.
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			fmt.Fprintln(w, line)
			continue
		}

		if !excludes[line[:colon]] {
			fmt.Fprintln(w, line)
		}
	}

	if err := w.Flush(); err != nil {
		return err
	}
	return scanner.Err()
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "filter-coverage: "+format+"\n", args...)
	os.Exit(1)
}
