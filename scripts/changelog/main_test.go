package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const valid = `# Changelog

Intro text.

## [Unreleased]

### Fixed

- Pending fix.

## [v1.1.0] - 2026-02-01

### Added

- Feature.

## [v1.0.0] - 2026-01-01

### Security

- Hardening.

[Unreleased]: https://example.com/compare/v1.1.0...HEAD
[v1.1.0]: https://example.com/compare/v1.0.0...v1.1.0
[v1.0.0]: https://example.com/releases/tag/v1.0.0
`

func TestValidateAcceptsWellFormedFile(t *testing.T) {
	if err := parse(valid).validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestValidateAcceptsCRLF(t *testing.T) {
	if err := parse(strings.ReplaceAll(valid, "\n", "\r\n")).validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]struct{ old, new, want string }{
		"unreleased not first": {"## [Unreleased]", "## [v1.2.0] - 2026-03-01", "first section"},
		"missing date":         {"## [v1.1.0] - 2026-02-01", "## [v1.1.0]", "needs a date"},
		"bad version":          {"## [v1.1.0] - 2026-02-01", "## [1.1.0] - 2026-02-01", "not a version"},
		"wrong order":          {"## [v1.1.0] - 2026-02-01", "## [v0.9.0] - 2026-02-01", "newest first"},
		"date order":           {"## [v1.0.0] - 2026-01-01", "## [v1.0.0] - 2026-03-01", "dated after"},
		"unknown subsection":   {"### Added", "### New stuff", "subsection"},
		"empty release":        {"- Feature.", "", "no entries"},
		"missing link":         {"[v1.0.0]: https://example.com/releases/tag/v1.0.0", "", "no link reference"},
		"duplicate":            {"## [v1.0.0] - 2026-01-01", "## [v1.1.0] - 2026-01-01", "duplicate"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := parse(strings.Replace(valid, tc.old, tc.new, 1)).validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestNotes(t *testing.T) {
	cl := parse(valid)
	got, err := cl.notes("v1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if got != "### Added\n\n- Feature." {
		t.Fatalf("notes = %q", got)
	}
	if _, err := cl.notes("v9.9.9"); err == nil {
		t.Fatal("want error for missing version")
	}
	if _, err := cl.notes(unreleased); err == nil {
		t.Fatal("want error for [Unreleased]")
	}
}

func TestLatest(t *testing.T) {
	got, err := parse(valid).latest()
	if err != nil || got != "v1.1.0" {
		t.Fatalf("latest() = %q, %v; want v1.1.0", got, err)
	}

	cl := parse(valid)
	if err := cl.release("v1.2.0", "2026-03-01"); err != nil {
		t.Fatal(err)
	}
	if got, _ := cl.latest(); got != "v1.2.0" {
		t.Fatalf("after release, latest() = %q; want v1.2.0", got)
	}

	onlyUnreleased := "# Changelog\n\n## [Unreleased]\n\n[Unreleased]: https://example.com\n"
	if _, err := parse(onlyUnreleased).latest(); err == nil {
		t.Fatal("want error when nothing has been released")
	}
	if _, err := parse(strings.Replace(valid, "## [Unreleased]", "## [v9.0.0]", 1)).latest(); err == nil {
		t.Fatal("want error for a malformed changelog")
	}
}

func TestReleaseMovesUnreleasedAndUpdatesLinks(t *testing.T) {
	cl := parse(valid)
	if err := cl.release("v1.2.0", "2026-03-01"); err != nil {
		t.Fatal(err)
	}
	out := cl.String()
	for _, want := range []string{
		"## [Unreleased]\n\n## [v1.2.0] - 2026-03-01\n\n### Fixed\n\n- Pending fix.\n",
		"[Unreleased]: " + repoURL + "/compare/v1.2.0...HEAD\n",
		"[v1.2.0]: " + repoURL + "/compare/v1.1.0...v1.2.0\n",
		"[v1.1.0]: https://example.com/compare/v1.0.0...v1.1.0\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n---\n%s", want, out)
		}
	}
	if strings.Contains(out, "compare/v1.1.0...HEAD") {
		t.Error("stale [Unreleased] link kept")
	}
	if err := parse(out).validate(); err != nil {
		t.Fatalf("released file does not validate: %v", err)
	}
}

func TestReleaseRejects(t *testing.T) {
	cases := map[string]struct{ version, date, text string }{
		"not newer":          {"v1.0.5", "2026-03-01", valid},
		"exists":             {"v1.1.0", "2026-03-01", valid},
		"bad version":        {"1.2.0", "2026-03-01", valid},
		"bad date":           {"v1.2.0", "March", valid},
		"nothing to release": {"v1.2.0", "2026-03-01", strings.Replace(valid, "- Pending fix.", "", 1)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := parse(tc.text).release(tc.version, tc.date); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v1.2.3", "v1.2.3", 0},
		{"v1.10.0", "v1.9.9", 1},
		{"v2.0.0", "v10.0.0", -1},
		{"v1.0.0-rc.1", "v1.0.0", -1},
		{"v1.0.0", "v1.0.0-rc.1", 1},
		{"v1.0.0-rc.1", "v1.0.0-rc.2", -1},
	}
	for _, tc := range cases {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compareVersions(%s, %s) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestRunModes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "CHANGELOG.md")
	if err := os.WriteFile(path, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(options{path: path, date: "2026-03-01"}); err == nil {
		t.Fatal("want error when no mode is given")
	}
	if err := run(options{path: path, check: true, latest: true}); err == nil {
		t.Fatal("want error when two modes are given")
	}
	if err := run(options{path: path, check: true}); err != nil {
		t.Fatalf("-check: %v", err)
	}
	if err := run(options{path: path, latest: true}); err != nil {
		t.Fatalf("-latest: %v", err)
	}
	if err := run(options{path: path, extract: "v1.0.0"}); err != nil {
		t.Fatalf("-extract: %v", err)
	}
	if err := run(options{path: path, release: "v1.2.0", date: "2026-03-01"}); err != nil {
		t.Fatalf("-release: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "## [v1.2.0] - 2026-03-01") {
		t.Fatalf("release not written:\n%s", data)
	}
}
