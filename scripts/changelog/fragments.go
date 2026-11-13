package main

// Changelog fragments. Every pull request adds its entry as a file of its own
// in changelog.d/ instead of editing CHANGELOG.md, so pull requests never
// conflict on the [Unreleased] section and merge in any order without a
// rebase (and a CI re-run). -release folds the fragments into the new
// version's section and deletes them.
//
// A fragment is named <name>.<type>.md, where <type> is the Keep a Changelog
// group in lower case (added, changed, deprecated, removed, fixed, security)
// and <name> is the issue number and a few words, e.g.
// changelog.d/484-audit-severity.changed.md. It holds one or more "- "
// entries; lines that continue an entry are indented.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const fragmentDir = "changelog.d"

// fragmentTypes are the groups in the order they appear in a release.
var fragmentTypes = []string{"added", "changed", "deprecated", "removed", "fixed", "security"}

var fragmentNameRe = regexp.MustCompile(`^[0-9a-z][0-9a-z_-]*\.(added|changed|deprecated|removed|fixed|security)\.md$`)

type fragment struct {
	file    string // base name
	group   string // "Added", "Changed", ...
	entries []string
}

// loadFragments reads every fragment in dir, sorted by file name. A missing
// dir has none. README.md is the folder's documentation, not a fragment.
func loadFragments(dir string) ([]fragment, error) {
	des, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var frags []fragment
	var problems []string
	for _, de := range des {
		name := de.Name()
		if de.IsDir() || name == "README.md" || name == ".gitkeep" {
			continue
		}
		m := fragmentNameRe.FindStringSubmatch(name)
		if m == nil {
			problems = append(problems, fmt.Sprintf("%s: name it <issue>-<words>.<type>.md, type one of %s", name, strings.Join(fragmentTypes, ", ")))
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- a file in the repo's changelog.d
		if err != nil {
			return nil, err
		}
		entries, err := parseFragment(string(data))
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		frags = append(frags, fragment{file: name, group: titleCase(m[1]), entries: entries})
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("%s:\n  %s", dir, strings.Join(problems, "\n  "))
	}
	sort.Slice(frags, func(i, j int) bool { return frags[i].file < frags[j].file })
	return frags, nil
}

// parseFragment returns the fragment's lines without surrounding blank lines,
// after checking that it is a list of "- " entries and nothing else.
func parseFragment(text string) ([]string, error) {
	lines := trimBlank(strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n"))
	if len(lines) == 0 {
		return nil, errors.New("empty; write the entry as a \"- \" line")
	}
	if !strings.HasPrefix(lines[0], "- ") {
		return nil, errors.New("must start with a \"- \" entry")
	}
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			return nil, errors.New("no headings: the file name sets the group")
		}
		if l != "" && !strings.HasPrefix(l, "- ") && !strings.HasPrefix(l, " ") && !strings.HasPrefix(l, "\t") {
			return nil, fmt.Errorf("line %q is neither a \"- \" entry nor indented under one", l)
		}
	}
	return lines, nil
}

func titleCase(s string) string { return strings.ToUpper(s[:1]) + s[1:] }

// foldFragments adds the fragments' entries to [Unreleased], grouped and
// ordered like a release, after any entries already there.
func (cl *changelog) foldFragments(frags []fragment) {
	if len(frags) == 0 {
		return
	}
	body := cl.sections[0].body
	var lead []string // lines before the first group (normally none)
	groups := map[string][]string{}
	cur := ""
	for _, l := range body {
		if m := subRe.FindStringSubmatch(l); m != nil {
			cur = m[1]
			continue
		}
		if cur == "" {
			lead = append(lead, l)
			continue
		}
		groups[cur] = append(groups[cur], l)
	}
	for _, f := range frags {
		groups[f.group] = append(trimBlank(groups[f.group]), f.entries...)
	}
	out := trimBlank(lead)
	for _, t := range fragmentTypes {
		g := trimBlank(groups[titleCase(t)])
		if len(g) == 0 {
			continue
		}
		if len(out) > 0 {
			out = append(out, "")
		}
		out = append(out, "### "+titleCase(t), "")
		out = append(out, g...)
	}
	cl.sections[0].body = out
}

// checkUnreleasedEmpty: entries go in changelog.d/, never straight into
// CHANGELOG.md, so two pull requests can't conflict there.
func (cl *changelog) checkUnreleasedEmpty() error {
	if hasEntries(cl.sections[0].body) {
		return fmt.Errorf("[Unreleased] has entries; move each to a file in %s/ (see %s/README.md)", fragmentDir, fragmentDir)
	}
	return nil
}
