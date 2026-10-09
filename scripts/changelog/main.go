// changelog keeps CHANGELOG.md usable as the single source of release notes.
//
// Modes:
//
//	go run ./scripts/changelog -check             # fail if CHANGELOG.md is malformed
//	go run ./scripts/changelog -extract v3.4.0    # print v3.4.0's notes (the GitHub release body)
//	go run ./scripts/changelog -release v3.4.0    # move [Unreleased] entries under a new v3.4.0 heading
//
// The file follows Keep a Changelog (https://keepachangelog.com/en/1.1.0/):
// an "## [Unreleased]" section first, then "## [vX.Y.Z] - YYYY-MM-DD" sections
// newest first, each grouped under "### Added/Changed/Deprecated/Removed/Fixed/Security",
// and a link reference for every heading at the bottom of the file.
//
// The release workflow publishes -extract's output as the release body, and
// the release trigger refuses to tag a version that has no section, so a
// release can't ship without human-written notes.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	repoURL    = "https://github.com/BrainStation-23/SentinelGo"
	unreleased = "Unreleased"
)

var (
	headingRe = regexp.MustCompile(`^## \[([^\]]+)\](?: - (\d{4}-\d{2}-\d{2}))?\s*$`)
	versionRe = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$`)
	linkRe    = regexp.MustCompile(`^\[([^\]]+)\]:\s+\S+`)
	subRe     = regexp.MustCompile(`^### (.+?)\s*$`)

	allowedSubsections = map[string]bool{
		"Added": true, "Changed": true, "Deprecated": true,
		"Removed": true, "Fixed": true, "Security": true,
	}
)

// section is one "## [name] - date" block. body holds the lines between this
// heading and the next one, without trailing link references.
type section struct {
	name string
	date string
	body []string
}

type changelog struct {
	preamble []string
	sections []section
	links    []string
}

func main() {
	path := flag.String("file", "CHANGELOG.md", "changelog to operate on")
	check := flag.Bool("check", false, "validate the changelog structure")
	extract := flag.String("extract", "", "print the notes for this version")
	release := flag.String("release", "", "move [Unreleased] entries under this new version")
	date := flag.String("date", time.Now().UTC().Format(time.DateOnly), "release date for -release")
	flag.Parse()

	if err := run(*path, *check, *extract, *release, *date); err != nil {
		fmt.Fprintln(os.Stderr, "changelog:", err)
		os.Exit(1)
	}
}

func run(path string, check bool, extract, release, date string) error {
	modes := 0
	for _, on := range []bool{check, extract != "", release != ""} {
		if on {
			modes++
		}
	}
	if modes != 1 {
		return errors.New("pass exactly one of -check, -extract or -release")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	cl := parse(string(data))

	switch {
	case check:
		if err := cl.validate(); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		fmt.Printf("%s: OK (%d releases)\n", path, len(cl.sections)-1)
		return nil
	case extract != "":
		notes, err := cl.notes(extract)
		if err != nil {
			return err
		}
		fmt.Println(notes)
		return nil
	default:
		if err := cl.validate(); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if err := cl.release(release, date); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(cl.String()), 0o644); err != nil { //nolint:gosec // G306: a tracked doc, not a secret
			return err
		}
		fmt.Printf("%s: moved [Unreleased] to [%s] - %s\n", path, release, date)
		return nil
	}
}

func parse(text string) *changelog {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	cl := &changelog{}
	var cur *section
	for _, line := range lines {
		if m := headingRe.FindStringSubmatch(line); m != nil {
			cl.sections = append(cl.sections, section{name: m[1], date: m[2]})
			cur = &cl.sections[len(cl.sections)-1]
			continue
		}
		switch {
		case cur == nil:
			cl.preamble = append(cl.preamble, line)
		case linkRe.MatchString(line):
			cl.links = append(cl.links, line)
		default:
			cur.body = append(cur.body, line)
		}
	}
	cl.preamble = trimBlank(cl.preamble)
	for i := range cl.sections {
		cl.sections[i].body = trimBlank(cl.sections[i].body)
	}
	return cl
}

func (cl *changelog) validate() error {
	if len(cl.sections) == 0 || cl.sections[0].name != unreleased {
		return errors.New("the first section must be ## [Unreleased]")
	}
	if cl.sections[0].date != "" {
		return errors.New("[Unreleased] must not have a date")
	}

	seen := map[string]bool{}
	for i := range cl.sections {
		s := &cl.sections[i]
		if seen[s.name] {
			return fmt.Errorf("duplicate section [%s]", s.name)
		}
		seen[s.name] = true
		if err := checkSubsections(s); err != nil {
			return err
		}
		if i == 0 {
			continue
		}
		var newer *section
		if i > 1 {
			newer = &cl.sections[i-1]
		}
		if err := checkRelease(s, newer); err != nil {
			return err
		}
	}
	return cl.checkLinks()
}

// checkRelease validates a version section against the next-newer release (nil for the newest).
func checkRelease(s, newer *section) error {
	if !versionRe.MatchString(s.name) {
		return fmt.Errorf("[%s] is not a version like v1.2.3", s.name)
	}
	if _, err := time.Parse(time.DateOnly, s.date); err != nil {
		return fmt.Errorf("[%s] needs a date like \"## [%s] - 2006-01-02\"", s.name, s.name)
	}
	if !hasEntries(s.body) {
		return fmt.Errorf("[%s] has no entries", s.name)
	}
	if newer == nil {
		return nil
	}
	if compareVersions(newer.name, s.name) <= 0 {
		return fmt.Errorf("[%s] must come after [%s]: list releases newest first", s.name, newer.name)
	}
	if newer.date < s.date {
		return fmt.Errorf("[%s] is dated after the newer [%s]", s.name, newer.name)
	}
	return nil
}

func (cl *changelog) checkLinks() error {
	linked := map[string]bool{}
	for _, l := range cl.links {
		linked[linkRe.FindStringSubmatch(l)[1]] = true
	}
	for _, s := range cl.sections {
		if !linked[s.name] {
			return fmt.Errorf("[%s] has no link reference at the bottom of the file", s.name)
		}
	}
	return nil
}

func checkSubsections(s *section) error {
	for _, line := range s.body {
		if m := subRe.FindStringSubmatch(line); m != nil && !allowedSubsections[m[1]] {
			return fmt.Errorf("[%s] has subsection %q; use Added, Changed, Deprecated, Removed, Fixed or Security", s.name, m[1])
		}
	}
	return nil
}

// notes returns a released version's body, ready to use as a release description.
func (cl *changelog) notes(version string) (string, error) {
	s := cl.find(version)
	if s == nil || version == unreleased {
		return "", fmt.Errorf("CHANGELOG.md has no [%s] section; add one before releasing", version)
	}
	if !hasEntries(s.body) {
		return "", fmt.Errorf("[%s] has no entries", version)
	}
	return strings.Join(s.body, "\n"), nil
}

// release turns the [Unreleased] entries into a new dated version section and
// leaves an empty [Unreleased] above it, updating the compare links to match.
func (cl *changelog) release(version, date string) error {
	if !versionRe.MatchString(version) {
		return fmt.Errorf("%q is not a version like v1.2.3", version)
	}
	if _, err := time.Parse(time.DateOnly, date); err != nil {
		return fmt.Errorf("invalid -date %q", date)
	}
	if cl.find(version) != nil {
		return fmt.Errorf("[%s] already exists", version)
	}
	prevVersion := ""
	if len(cl.sections) > 1 {
		prevVersion = cl.sections[1].name
		if compareVersions(version, prevVersion) <= 0 {
			return fmt.Errorf("%s is not newer than the latest release %s", version, prevVersion)
		}
	}
	if !hasEntries(cl.sections[0].body) {
		return errors.New("[Unreleased] has no entries to release")
	}

	released := section{name: version, date: date, body: cl.sections[0].body}
	cl.sections[0].body = nil
	cl.sections = append(cl.sections[:1], append([]section{released}, cl.sections[1:]...)...)

	versionLink := fmt.Sprintf("[%s]: %s/releases/tag/%s", version, repoURL, version)
	if prevVersion != "" {
		versionLink = fmt.Sprintf("[%s]: %s/compare/%s...%s", version, repoURL, prevVersion, version)
	}
	links := []string{fmt.Sprintf("[%s]: %s/compare/%s...HEAD", unreleased, repoURL, version), versionLink}
	for _, l := range cl.links {
		if linkRe.FindStringSubmatch(l)[1] != unreleased {
			links = append(links, l)
		}
	}
	cl.links = links
	return nil
}

func (cl *changelog) find(name string) *section {
	for i := range cl.sections {
		if cl.sections[i].name == name {
			return &cl.sections[i]
		}
	}
	return nil
}

func (cl *changelog) String() string {
	var b strings.Builder
	b.WriteString(strings.Join(cl.preamble, "\n"))
	b.WriteString("\n")
	for _, s := range cl.sections {
		b.WriteString("\n## [" + s.name + "]")
		if s.date != "" {
			b.WriteString(" - " + s.date)
		}
		b.WriteString("\n")
		if len(s.body) > 0 {
			b.WriteString("\n" + strings.Join(s.body, "\n") + "\n")
		}
	}
	if len(cl.links) > 0 {
		b.WriteString("\n" + strings.Join(cl.links, "\n") + "\n")
	}
	return b.String()
}

func hasEntries(body []string) bool {
	for _, line := range body {
		if strings.HasPrefix(strings.TrimSpace(line), "- ") {
			return true
		}
	}
	return false
}

func trimBlank(lines []string) []string {
	for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		lines = lines[1:]
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// compareVersions orders vX.Y.Z[-pre] tags. A pre-release sorts before its
// release; two pre-releases of the same version compare as strings.
func compareVersions(a, b string) int {
	ma, mb := versionRe.FindStringSubmatch(a), versionRe.FindStringSubmatch(b)
	if ma == nil || mb == nil {
		return strings.Compare(a, b)
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(ma[i])
		y, _ := strconv.Atoi(mb[i])
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case ma[4] == mb[4]:
		return 0
	case ma[4] == "":
		return 1
	case mb[4] == "":
		return -1
	default:
		return strings.Compare(ma[4], mb[4])
	}
}
