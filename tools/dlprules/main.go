// Command dlprules turns the betterleaks secrets ruleset (TOML) into the
// rules.json the agent embeds (internal/dlp/detect/secrets), plus the detector
// catalog seed for the backend (sentinel-ops#466).
//
// It is a separate module so its TOML parser is never linked into the agent.
// Run it through scripts/update-dlp-rules.sh, which pins the upstream tag:
//
//	go run . -in betterleaks.toml -tag v1.9.0 -commit <sha> \
//	    -out ../../internal/dlp/detect/secrets/rules.json -catalog catalog.json
//
// Translation rules (see translateFilter for filter shapes):
//   - Only rules with confidence high or medium ship.
//   - Rules scoped to file paths (path = ...) or without a regex are dropped: a
//     clipboard has no path.
//   - A rule whose filter has an unknown shape is dropped and listed, never
//     shipped with a weaker filter.
//   - validate, analyze, revoke, prefilter, skipReport and components are
//     ignored: the agent never makes network calls, and every rule reports on
//     its own.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Ruleset is the generated rules.json.
type Ruleset struct {
	Source       Source    `json:"source"`
	GlobalFilter Filter    `json:"global_filter"`
	Rules        []Rule    `json:"rules"`
	Dropped      []Dropped `json:"dropped"`
}

// Source records exactly which upstream file the rules came from.
type Source struct {
	Repo    string `json:"repo"`
	Tag     string `json:"tag"`
	Commit  string `json:"commit"`
	SHA256  string `json:"sha256"`
	License string `json:"license"`
}

// Rule is one shipped secret rule.
type Rule struct {
	ID          string   `json:"id"`
	Confidence  string   `json:"confidence"`
	Regex       string   `json:"regex"`
	SecretGroup int      `json:"secret_group,omitempty"`
	Keywords    []string `json:"keywords,omitempty"`
	Filter      *Filter  `json:"filter,omitempty"`
}

// Dropped is a rule left out, and why.
type Dropped struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// CatalogEntry is one detector row for the backend catalog.
type CatalogEntry struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Confidence  string `json:"confidence"`
}

// upstream is the subset of the betterleaks TOML the generator reads.
type upstream struct {
	Filter string         `toml:"filter"`
	Rules  []upstreamRule `toml:"rules"`
}

type upstreamRule struct {
	ID          string   `toml:"id"`
	Description string   `toml:"description"`
	Regex       string   `toml:"regex"`
	Path        string   `toml:"path"`
	SecretGroup int      `toml:"secretGroup"`
	ValueGroup  int      `toml:"valueGroup"`
	Keywords    []string `toml:"keywords"`
	Confidence  string   `toml:"confidence"`
	Filter      string   `toml:"filter"`
}

func main() {
	in := flag.String("in", "", "betterleaks TOML ruleset")
	tag := flag.String("tag", "", "upstream tag the TOML was taken from")
	commit := flag.String("commit", "", "upstream commit of that tag")
	out := flag.String("out", "rules.json", "rules.json to write")
	catalog := flag.String("catalog", "", "detector catalog seed to write (optional)")
	flag.Parse()
	if *in == "" || *tag == "" || *commit == "" {
		fmt.Fprintln(os.Stderr, "usage: dlprules -in <toml> -tag <tag> -commit <sha> [-out rules.json] [-catalog catalog.json]")
		os.Exit(2)
	}
	if err := run(*in, *tag, *commit, *out, *catalog, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "dlprules:", err)
		os.Exit(1)
	}
}

func run(in, tag, commit, out, catalogOut string, report io.Writer) error {
	data, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	src := Source{Repo: "github.com/betterleaks/betterleaks", Tag: tag, Commit: commit, License: "MIT"}
	rs, cat, err := generate(data, src)
	if err != nil {
		return err
	}
	if err := writeJSON(out, rs); err != nil {
		return err
	}
	if catalogOut != "" {
		if err := writeJSON(catalogOut, cat); err != nil {
			return err
		}
	}
	_, _ = fmt.Fprintf(report, "%d rules shipped, %d dropped\n", len(rs.Rules), len(rs.Dropped))
	for _, d := range rs.Dropped {
		_, _ = fmt.Fprintf(report, "  dropped %-45s %s\n", d.ID, d.Reason)
	}
	return nil
}

// generate translates the TOML ruleset. The global filter must translate, or
// generation fails: shipping without it would flood users with placeholders.
func generate(data []byte, src Source) (*Ruleset, []CatalogEntry, error) {
	var up upstream
	if err := toml.Unmarshal(data, &up); err != nil {
		return nil, nil, fmt.Errorf("parse TOML: %w", err)
	}
	sum := sha256.Sum256(data)
	src.SHA256 = hex.EncodeToString(sum[:])

	global, err := translateFilter(up.Filter)
	if err != nil {
		return nil, nil, fmt.Errorf("global filter: %w", err)
	}
	global.encodeLiterals()
	rs := &Ruleset{Source: src, GlobalFilter: global, Rules: []Rule{}, Dropped: []Dropped{}}
	var cat []CatalogEntry
	for _, ur := range up.Rules {
		r, reason := translateRule(ur)
		if reason != "" {
			rs.Dropped = append(rs.Dropped, Dropped{ID: ur.ID, Reason: reason})
			continue
		}
		rs.Rules = append(rs.Rules, r)
		cat = append(cat, CatalogEntry{ID: "secrets." + r.ID, Description: ur.Description, Confidence: r.Confidence})
	}
	if len(rs.Rules) == 0 {
		return nil, nil, errors.New("no rules shipped")
	}
	sort.Slice(rs.Rules, func(i, j int) bool { return rs.Rules[i].ID < rs.Rules[j].ID })
	sort.Slice(rs.Dropped, func(i, j int) bool { return rs.Dropped[i].ID < rs.Dropped[j].ID })
	sort.Slice(cat, func(i, j int) bool { return cat[i].ID < cat[j].ID })
	return rs, cat, nil
}

// translateRule returns the shipped rule, or the reason it was dropped.
func translateRule(ur upstreamRule) (Rule, string) {
	switch {
	case ur.ID == "":
		return Rule{}, "no id"
	case ur.Confidence != "high" && ur.Confidence != "medium":
		return Rule{}, "confidence " + ur.Confidence
	case ur.Path != "":
		return Rule{}, "scoped to file paths"
	case ur.Regex == "":
		return Rule{}, "no regex"
	}
	re, err := regexp.Compile(ur.Regex)
	if err != nil {
		return Rule{}, "regex does not compile with RE2: " + err.Error()
	}
	group := ur.SecretGroup
	if ur.ValueGroup != 0 {
		group = ur.ValueGroup
	}
	if group > re.NumSubexp() {
		return Rule{}, fmt.Sprintf("secret group %d out of range", group)
	}
	r := Rule{ID: ur.ID, Confidence: ur.Confidence, Regex: ur.Regex, SecretGroup: group}
	for _, k := range ur.Keywords {
		r.Keywords = append(r.Keywords, strings.ToLower(k))
	}
	f, err := translateFilter(ur.Filter)
	if err != nil {
		return Rule{}, err.Error()
	}
	f.encodeLiterals()
	if !f.empty() {
		r.Filter = &f
	}
	return r, ""
}

func (f Filter) empty() bool {
	return f.EntropyBelow == 0 && f.EntropyAtMost == 0 && len(f.DenyRegex) == 0 &&
		len(f.DenyContainsHex) == 0 && len(f.DenyMatchRegex) == 0 && len(f.RequireRegex) == 0
}

// writeJSON writes v as indented JSON without HTML escaping, so regexes stay
// readable in diffs.
func writeJSON(path string, v any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(v); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644) // #nosec G306 -- generated source file, not a secret
}
