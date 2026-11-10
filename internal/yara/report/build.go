// Package report turns threat hunting scan results into the match and
// scan-summary events of contract §3 (#415), queues them on disk and
// uploads them with agent_enqueue_yara_events.
//
// Privacy (hard rule): events carry identifiers ($s1), hashes, sizes and
// metadata only. Nothing here reads files, and nothing may log, store or
// send matched bytes, excerpts or file content (privacy_test.go).
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"sentinelgo/internal/yara"
)

// MaxMatchEventsPerScan caps the match events one scan sends (#415): one
// bad rule matching every file must not flood the backend. Past it the scan
// summary says truncated.
const MaxMatchEventsPerScan = 5000

// Hit is one rule that matched a file, as the scan worker reports it.
type Hit struct {
	RulesetID       string
	RulesetRevision int
	Rule            string
	Namespace       string
	Tags            []string
	// Meta is the rule's metadata (not the file's).
	Meta map[string]any
	// StringIDs are the identifiers of the strings that matched ($s1),
	// never what they matched.
	StringIDs []string
}

// FileResult is a scanned file that matched. SHA256 and Size come from the
// worker's single pass over the file (#415: no second read).
type FileResult struct {
	Path   string
	SHA256 string
	Size   int64
	MTime  time.Time
	Hits   []Hit
}

// Dedupe remembers the matches already reported (store.YARAEventStore), so
// later scheduled scans don't send them again.
type Dedupe interface {
	Reported(keys []string) (map[string]bool, error)
	MarkReported(keys []string) error
}

// Scan builds one scan's events.
type Scan struct {
	ID      string
	Trigger string
	Preset  string
	Started time.Time

	hashPaths bool
	dedupe    Dedupe
	owner     func(path string) string
	now       func() time.Time

	found     int64 // matches found, reported or not
	sent      int   // match events built
	truncated bool
}

// NewScan starts a scan's reporting. id is the server's scan id for an
// on-demand scan; "" mints one. dedupe is used for scheduled scans only:
// on-demand scans always report, so admins can confirm a file is still
// there.
func NewScan(id, trigger, preset string, evidence yara.Evidence, dedupe Dedupe) *Scan {
	if id == "" {
		id = yara.NewID()
	}
	s := &Scan{ID: id, Trigger: trigger, Preset: preset, Started: time.Now().UTC(),
		hashPaths: evidence.HashPaths(), owner: newOwnerCache().lookup, now: time.Now}
	if trigger == yara.TriggerScheduled {
		s.dedupe = dedupe
	}
	return s
}

// Matches returns the events for a matched file: one per hit, minus hits
// already reported (scheduled scans) and hits past the per-scan cap. Each
// event is valid under §3.
func (s *Scan) Matches(r FileResult) ([]yara.Event, error) {
	if len(r.Hits) == 0 {
		return nil, nil
	}
	if !yara.IsSHA256(r.SHA256) {
		return nil, fmt.Errorf("report: file result without a SHA-256")
	}
	s.found += int64(len(r.Hits))
	hits := r.Hits
	var keys []string
	if s.dedupe != nil {
		keys = make([]string, len(hits))
		for i, h := range hits {
			keys[i] = dedupeKey(r.SHA256, r.Path, h)
		}
		done, err := s.dedupe.Reported(keys)
		if err != nil {
			return nil, err
		}
		var newHits []Hit
		var newKeys []string
		for i, h := range hits {
			if !done[keys[i]] {
				newHits, newKeys = append(newHits, h), append(newKeys, keys[i])
			}
		}
		hits, keys = newHits, newKeys
	}
	if room := MaxMatchEventsPerScan - s.sent; len(hits) > room {
		s.truncated = true
		hits = hits[:max(room, 0)]
		if keys != nil {
			keys = keys[:len(hits)]
		}
	}
	if len(hits) == 0 {
		return nil, nil
	}
	path, pathHash, ext := s.pathEvidence(r.Path)
	owner := yara.Truncate(s.owner(r.Path), yara.MaxOwnerLen)
	now := s.now().UTC()
	out := make([]yara.Event, 0, len(hits))
	for _, h := range hits {
		m := &yara.Match{
			ScanID: s.ID, Trigger: s.Trigger,
			RulesetID: h.RulesetID, RulesetRevision: max(h.RulesetRevision, 0),
			Rule:      yara.Truncate(h.Rule, yara.MaxRuleLen),
			Namespace: yara.Truncate(h.Namespace, yara.MaxRuleLen),
			Tags:      cleanTags(h.Tags), Meta: cleanMeta(h.Meta), StringIDs: cleanStringIDs(h.StringIDs),
			Path: path, PathHash: pathHash, FileExt: ext,
			SHA256: strings.ToLower(r.SHA256), Size: max(r.Size, 0), MTime: r.MTime.UTC(),
			Owner: owner, DetectedAt: now,
		}
		if !yara.IsUUID(m.RulesetID) {
			m.RulesetID = ""
		}
		ev := yara.Event{EventID: yara.NewID(), Match: m}
		if err := ev.Validate(); err != nil {
			return nil, err // a rule name the server won't take (empty)
		}
		out = append(out, ev)
	}
	s.sent += len(out)
	if s.dedupe != nil {
		if err := s.dedupe.MarkReported(keys); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Summary returns the scan_summary event (also the status's last_scan).
func (s *Scan) Summary(state string, filesScanned, filesSkipped, errs int64) yara.Event {
	return yara.Event{EventID: yara.NewID(), Summary: s.SummaryBody(state, filesScanned, filesSkipped, errs)}
}

// SummaryBody is the summary without an event id, for the status.
func (s *Scan) SummaryBody(state string, filesScanned, filesSkipped, errs int64) *yara.ScanSummary {
	return &yara.ScanSummary{
		ScanID: s.ID, Trigger: s.Trigger, Preset: s.Preset,
		StartedAt: s.Started, FinishedAt: s.now().UTC(), State: state,
		FilesScanned: max(filesScanned, 0), FilesSkipped: max(filesSkipped, 0), Errors: max(errs, 0),
		Matches: s.found, Truncated: s.truncated,
	}
}

// pathEvidence returns the path (full mode), or its hash and extension.
// A path over the server's limit is hashed in either mode.
func (s *Scan) pathEvidence(p string) (path, pathHash *string, ext string) {
	if !s.hashPaths && p != "" && len(p) <= yara.MaxPathLen {
		return &p, nil, ""
	}
	h := HashPath(p)
	return nil, &h, FileExt(p)
}

// HashPath is the hashed path mode's path_hash: the SHA-256 of the
// lower-cased path.
func HashPath(p string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(p)))
	return hex.EncodeToString(sum[:])
}

// FileExt is the file name's last extension, lower-cased, without the dot,
// at most 32 bytes (the backend's _yara_file_ext).
func FileExt(p string) string {
	name := p[strings.LastIndexAny(p, `/\`)+1:]
	i := strings.LastIndexByte(name, '.')
	if i < 0 || i == len(name)-1 {
		return ""
	}
	return yara.Truncate(strings.ToLower(name[i+1:]), yara.MaxFileExtLen)
}

// dedupeKey identifies a match for device de-dup: (sha256, path, rule,
// ruleset revision), hashed so the store holds no paths.
func dedupeKey(sha, path string, h Hit) string {
	sum := sha256.Sum256([]byte(strings.ToLower(sha) + "\x00" + path + "\x00" +
		h.RulesetID + "\x00" + h.Namespace + "\x00" + h.Rule + "\x00" + fmt.Sprint(h.RulesetRevision)))
	return hex.EncodeToString(sum[:16])
}

func cleanTags(tags []string) []string {
	var out []string
	for _, t := range tags {
		if t = yara.Truncate(t, yara.MaxTagLen); t != "" && len(out) < yara.MaxTags {
			out = append(out, t)
		}
	}
	return out
}

func cleanStringIDs(ids []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, id := range ids {
		if yara.IsStringID(id) && !seen[id] && len(out) < yara.MaxStringIDs {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// cleanMeta keeps string, number and boolean values, adding keys in name
// order while the encoded object stays within 2 KB. Long strings are cut.
func cleanMeta(meta map[string]any) map[string]any {
	if len(meta) == 0 {
		return nil
	}
	keys := make([]string, 0, len(meta))
	for k := range meta {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := map[string]any{}
	for _, k := range keys {
		var v any
		switch x := meta[k].(type) {
		case string:
			v = yara.Truncate(x, 512)
		case bool, float64, int64, json.Number:
			v = x
		case int:
			v = int64(x)
		case int32:
			v = int64(x)
		case uint32:
			v = int64(x)
		case float32:
			v = float64(x)
		default:
			continue
		}
		out[k] = v
		if data, err := json.Marshal(out); err != nil || len(data) > yara.MaxMetaBytes {
			delete(out, k)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
