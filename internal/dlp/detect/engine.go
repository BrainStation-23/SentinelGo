// Package detect scans text for sensitive data: secrets (the betterleaks
// ruleset, embedded as data), PII (Presidio-port recognizers with checksum
// validators) and admin-defined regex and keyword rules from the policy. It is
// pure and deterministic, does no I/O and runs inside the session helper.
//
// The raw matched text never leaves this package: a Finding carries the
// detector id, the count, a masked form and a SHA-256, plus offsets so a
// caller with evidence_mode=full can cut its own excerpt.
package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"sentinelgo/internal/dlp/detect/custom"
	"sentinelgo/internal/dlp/detect/pii"
	"sentinelgo/internal/dlp/detect/secrets"
)

// DefaultMaxScanBytes is how much of a text is scanned when the bundle doesn't
// say. The rest isn't scanned and the result is marked truncated.
const DefaultMaxScanBytes = 1 << 20

// SecretsAll is the detector id that stands for every shipped secret rule.
const SecretsAll = "secrets.all"

const secretsPrefix = "secrets."

// Policy match modes.
const (
	MatchAny = "any"
	MatchAll = "all"
)

// Rule is one detector entry of a policy, as the bundle carries it.
type Rule struct {
	DetectorID    string
	RuleID        string
	MinCount      int
	Pattern       string   // custom.regex
	Keywords      []string // custom.keywords
	CaseSensitive bool     // custom.keywords
}

// CompileError is a rule the engine skipped. The other rules stay active.
type CompileError struct {
	RuleID     string `json:"rule_id"`
	DetectorID string `json:"detector_id,omitempty"`
	Error      string `json:"error"`
}

// Finding is what one detector found, without the matched text.
type Finding struct {
	DetectorID string   // e.g. "secrets.aws-access-token", "pii.credit_card", "custom.regex"
	RuleID     string   // the bundle's rule_id, for custom rules
	Count      int      // number of matches
	Masked     string   // first match, masked (see Mask)
	SHA256     string   // hex SHA-256 of the first match
	Offsets    [][2]int // byte offsets of every match in the scanned text
}

// Result is the outcome of one Scan.
type Result struct {
	Findings     []Finding
	Truncated    bool // the text was longer than the scan limit
	ScannedBytes int
}

// Engine scans text with a fixed set of detectors. It is safe for concurrent
// use.
type Engine struct {
	secrets    *secrets.Ruleset
	secretsAll bool
	secretIDs  map[string]bool
	pii        *pii.Scanner
	custom     []*custom.Rule
	maxScan    int
	inactive   map[string]bool // rule ids skipped at compile time
}

// New builds an engine for rules. maxScanBytes <= 0 means
// DefaultMaxScanBytes. Rules with an unsupported detector id or a custom
// pattern that doesn't compile are skipped and returned as compile errors.
func New(rules []Rule, maxScanBytes int) (*Engine, []CompileError) {
	if maxScanBytes <= 0 {
		maxScanBytes = DefaultMaxScanBytes
	}
	b := &builder{e: &Engine{secretIDs: map[string]bool{}, maxScan: maxScanBytes, inactive: map[string]bool{}}}
	b.rs, b.rsErr = secrets.Load()
	var piiRules []Rule
	for _, r := range rules {
		switch {
		case r.DetectorID == custom.RegexID || r.DetectorID == custom.KeywordsID:
			b.addCustom(r)
		case strings.HasPrefix(r.DetectorID, secretsPrefix):
			b.addSecret(r)
		case strings.HasPrefix(r.DetectorID, "pii."):
			piiRules = append(piiRules, r)
		default:
			b.fail(r, errUnsupported(r))
		}
	}
	b.addPII(piiRules)
	if b.e.secretsAll || len(b.e.secretIDs) > 0 {
		b.e.secrets = b.rs
	}
	return b.e, b.errs
}

// builder collects an Engine's detectors and compile errors for New.
type builder struct {
	e     *Engine
	errs  []CompileError
	rs    *secrets.Ruleset
	rsErr error
}

func errUnsupported(r Rule) error { return fmt.Errorf("unsupported detector %q", r.DetectorID) }

func (b *builder) fail(r Rule, err error) {
	b.errs = append(b.errs, CompileError{RuleID: r.RuleID, DetectorID: r.DetectorID, Error: err.Error()})
	b.e.inactive[r.RuleID] = true
}

func (b *builder) addCustom(r Rule) {
	cr, err := custom.Compile(custom.Spec{
		DetectorID: r.DetectorID, RuleID: r.RuleID, Pattern: r.Pattern,
		Keywords: r.Keywords, CaseSensitive: r.CaseSensitive,
	})
	if err != nil {
		b.fail(r, err)
		return
	}
	b.e.custom = append(b.e.custom, cr)
}

func (b *builder) addSecret(r Rule) {
	id := strings.TrimPrefix(r.DetectorID, secretsPrefix)
	switch {
	case b.rsErr != nil:
		b.fail(r, b.rsErr)
	case r.DetectorID == SecretsAll:
		b.e.secretsAll = true
	case b.rs.Has(id):
		b.e.secretIDs[id] = true
	default:
		b.fail(r, errUnsupported(r))
	}
}

func (b *builder) addPII(rules []Rule) {
	if len(rules) == 0 {
		return
	}
	ids := make([]string, 0, len(rules))
	for _, r := range rules {
		ids = append(ids, r.DetectorID)
	}
	var unknown []string
	b.e.pii, unknown = pii.New(ids)
	for _, r := range rules {
		if slices.Contains(unknown, r.DetectorID) {
			b.fail(r, errUnsupported(r))
		}
	}
}

// SupportedDetectors lists every detector id this agent can run, sorted. It is
// reported to the backend so the console can flag policies a device can't
// enforce.
func SupportedDetectors() []string {
	ids := []string{SecretsAll, custom.RegexID, custom.KeywordsID}
	if rs, err := secrets.Load(); err == nil {
		for _, id := range rs.IDs() {
			ids = append(ids, secretsPrefix+id)
		}
	}
	for _, d := range pii.Detectors() {
		ids = append(ids, d.ID)
	}
	sort.Strings(ids)
	return ids
}

// Scan runs every detector over text (up to the scan limit).
func (e *Engine) Scan(text string) Result {
	res := Result{}
	if len(text) > e.maxScan {
		text = truncate(text, e.maxScan)
		res.Truncated = true
	}
	res.ScannedBytes = len(text)

	g := grouper{text: text, idx: map[[2]string]int{}}
	if e.secrets != nil {
		enabled := func(id string) bool { return e.secretsAll || e.secretIDs[id] }
		for _, m := range e.secrets.Find(text, enabled) {
			g.add(secretsPrefix+m.RuleID, "", m.Start, m.End)
		}
	}
	for _, m := range e.pii.Find(text) {
		g.add(m.DetectorID, "", m.Start, m.End)
	}
	for _, r := range e.custom {
		for _, m := range r.Find(text) {
			g.add(m.DetectorID, m.RuleID, m.Start, m.End)
		}
	}
	res.Findings = g.findings()
	return res
}

// grouper collects matches into one Finding per (detector, rule).
type grouper struct {
	text string
	idx  map[[2]string]int
	out  []Finding
}

func (g *grouper) add(detectorID, ruleID string, start, end int) {
	key := [2]string{detectorID, ruleID}
	i, ok := g.idx[key]
	if !ok {
		match := g.text[start:end]
		sum := sha256.Sum256([]byte(match))
		g.out = append(g.out, Finding{
			DetectorID: detectorID, RuleID: ruleID,
			Masked: Mask(match), SHA256: hex.EncodeToString(sum[:]),
		})
		i = len(g.out) - 1
		g.idx[key] = i
	}
	g.out[i].Count++
	g.out[i].Offsets = append(g.out[i].Offsets, [2]int{start, end})
}

func (g *grouper) findings() []Finding {
	sort.Slice(g.out, func(i, j int) bool {
		if g.out[i].DetectorID != g.out[j].DetectorID {
			return g.out[i].DetectorID < g.out[j].DetectorID
		}
		return g.out[i].RuleID < g.out[j].RuleID
	})
	return g.out
}

// Evaluate reports whether res satisfies a policy's rules under match ("all":
// every rule; anything else: at least one), and returns the findings that
// counted. A rule is satisfied when its detector found at least MinCount
// matches (1 when unset); secrets.all counts every secret rule. Rules skipped
// at compile time are left out, so one bad rule never disables the rest.
func (e *Engine) Evaluate(match string, rules []Rule, res Result) (bool, []Finding) {
	used := map[int]bool{}
	active, satisfied := 0, 0
	for _, r := range rules {
		if e.inactive[r.RuleID] {
			continue
		}
		active++
		if hits, ok := satisfies(r, res.Findings); ok {
			satisfied++
			for _, i := range hits {
				used[i] = true
			}
		}
	}
	ok := satisfied > 0
	if match == MatchAll {
		ok = active > 0 && satisfied == active
	}
	if !ok {
		return false, nil
	}
	var out []Finding
	for i, f := range res.Findings {
		if used[i] {
			out = append(out, f)
		}
	}
	return true, out
}

// satisfies reports whether findings meet r's minimum count, and which
// findings counted toward it.
func satisfies(r Rule, findings []Finding) ([]int, bool) {
	count := 0
	var hits []int
	for i, f := range findings {
		if counts(r, f) {
			count += f.Count
			hits = append(hits, i)
		}
	}
	return hits, count >= max(1, r.MinCount)
}

// counts reports whether finding f counts toward rule r.
func counts(r Rule, f Finding) bool {
	switch r.DetectorID {
	case SecretsAll:
		return strings.HasPrefix(f.DetectorID, secretsPrefix)
	case custom.RegexID, custom.KeywordsID:
		return f.DetectorID == r.DetectorID && f.RuleID == r.RuleID
	default:
		return f.DetectorID == r.DetectorID
	}
}

// maxMaskStars caps the masked middle, so a long secret (a private key) doesn't
// produce a long string of stars.
const maxMaskStars = 12

// Mask hides all but at most the first 4 and last 4 characters of s, and
// fewer for short values: a quarter of the length on each side, so at least
// half is always hidden.
func Mask(s string) string {
	r := []rune(s)
	n := len(r)
	keep := min(4, n/4)
	stars := min(n-2*keep, maxMaskStars)
	return string(r[:keep]) + strings.Repeat("*", stars) + string(r[n-keep:])
}

// truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncate(s string, n int) string {
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
