package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// noPending is valid with nothing under [Unreleased], as CHANGELOG.md is
// between releases once entries live in changelog.d/.
var noPending = strings.Replace(valid, "### Fixed\n\n- Pending fix.\n\n", "", 1)

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoadFragments(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"README.md":              "# How to\n",
		"20-b.fixed.md":          "- Fix B.\r\n",
		"10-a.added.md":          "\n- Add A.\n  More about A.\n- Add A2.\n\n",
		"30-c.security.md":       "- Patch C (CVE-2026-0001).\n",
		"40-d.changed.md":        "- Change D.\n  - detail\n",
		"50-e-with_under.fix.md": "",
	})
	if _, err := loadFragments(dir); err == nil || !strings.Contains(err.Error(), "50-e-with_under.fix.md") {
		t.Fatalf("want an error naming the bad file, got %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "50-e-with_under.fix.md")); err != nil {
		t.Fatal(err)
	}
	frags, err := loadFragments(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range frags {
		got = append(got, f.file+":"+f.group+":"+strings.Join(f.entries, "|"))
	}
	want := []string{
		"10-a.added.md:Added:- Add A.|  More about A.|- Add A2.",
		"20-b.fixed.md:Fixed:- Fix B.",
		"30-c.security.md:Security:- Patch C (CVE-2026-0001).",
		"40-d.changed.md:Changed:- Change D.|  - detail",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("fragments:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestLoadFragments_MissingDir(t *testing.T) {
	frags, err := loadFragments(filepath.Join(t.TempDir(), "none"))
	if err != nil || len(frags) != 0 {
		t.Fatalf("got %v, %v; want none", frags, err)
	}
}

func TestParseFragmentRejects(t *testing.T) {
	cases := map[string]string{
		"empty":        "\n\n",
		"no bullet":    "Fixed a thing.\n",
		"heading":      "- Entry.\n### Fixed\n",
		"stray line":   "- Entry.\nnot indented\n",
		"leading text": "Intro\n- Entry.\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseFragment(text); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestFragmentNames(t *testing.T) {
	for name, ok := range map[string]bool{
		"484-audit-severity.changed.md": true,
		"484.fixed.md":                  true,
		"dependabot_go.security.md":     true,
		"484-audit.Changed.md":          false,
		"484-audit.change.md":           false,
		"484 audit.fixed.md":            false,
		"-484.fixed.md":                 false,
		"484.fixed.txt":                 false,
	} {
		if got := fragmentNameRe.MatchString(name); got != ok {
			t.Errorf("%q: match = %v, want %v", name, got, ok)
		}
	}
}

// TestReleaseFoldsFragments: -release puts the fragments under the new
// version in Keep a Changelog order, after entries already in [Unreleased],
// and deletes them; -check then passes.
func TestReleaseFoldsFragments(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "CHANGELOG.md")
	dir := filepath.Join(tmp, "changelog.d")
	writeFiles(t, tmp, map[string]string{"CHANGELOG.md": valid}) // [Unreleased] has "- Pending fix." under Fixed
	writeFiles(t, dir, map[string]string{
		"README.md":       "# How to\n",
		"2-b.fixed.md":    "- Fix B.\n",
		"1-a.added.md":    "- Add A.\n",
		"3-c.security.md": "- Patch C.\n",
	})
	if err := run(options{path: path, dir: dir, release: "v1.2.0", date: "2026-03-01"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "## [Unreleased]\n\n## [v1.2.0] - 2026-03-01\n\n### Added\n\n- Add A.\n\n### Fixed\n\n- Pending fix.\n- Fix B.\n\n### Security\n\n- Patch C.\n\n## [v1.1.0]"
	if !strings.Contains(string(data), want) {
		t.Fatalf("released file:\n%s\nwant it to contain:\n%s", data, want)
	}
	left, _ := os.ReadDir(dir)
	if len(left) != 1 || left[0].Name() != "README.md" {
		t.Fatalf("fragments left after release: %v", left)
	}
	if err := run(options{path: path, dir: dir, check: true}); err != nil {
		t.Fatalf("-check after release: %v", err)
	}
}

// TestRelease_OnlyFragments: an empty [Unreleased] plus fragments releases,
// and with neither there is nothing to release.
func TestRelease_OnlyFragments(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "CHANGELOG.md")
	dir := filepath.Join(tmp, "changelog.d")
	writeFiles(t, tmp, map[string]string{"CHANGELOG.md": noPending})
	if err := run(options{path: path, dir: dir, check: true}); err != nil {
		t.Fatalf("-check with nothing pending: %v", err)
	}
	if err := run(options{path: path, dir: dir, release: "v1.2.0", date: "2026-03-01"}); err == nil {
		t.Fatal("want error: nothing to release")
	}
	writeFiles(t, dir, map[string]string{"7-x.changed.md": "- Change X.\n"})
	if err := run(options{path: path, dir: dir, release: "v1.2.0", date: "2026-03-01"}); err != nil {
		t.Fatal(err)
	}
	cl := parse(mustRead(t, path))
	if notes, err := cl.notes("v1.2.0"); err != nil || notes != "### Changed\n\n- Change X." {
		t.Fatalf("notes = %q, %v", notes, err)
	}
}

// TestCheck_BadFragment: -check fails on a malformed fragment.
func TestCheck_BadFragment(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "CHANGELOG.md")
	dir := filepath.Join(tmp, "changelog.d")
	writeFiles(t, tmp, map[string]string{"CHANGELOG.md": noPending})
	writeFiles(t, dir, map[string]string{"9.fixed.md": "### Fixed\n- x\n"})
	if err := run(options{path: path, dir: dir, check: true}); err == nil {
		t.Fatal("want error for a fragment with a heading")
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
