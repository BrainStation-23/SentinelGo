package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/yara"
)

const (
	rsID = "6f1c2a40-1111-4c3b-9a55-0123456789ab"
	sha  = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
)

// memDedupe is an in-memory Dedupe.
type memDedupe map[string]bool

func (m memDedupe) Reported(keys []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, k := range keys {
		if m[k] {
			out[k] = true
		}
	}
	return out, nil
}

func (m memDedupe) MarkReported(keys []string) error {
	for _, k := range keys {
		m[k] = true
	}
	return nil
}

func testScan(trigger string, ev yara.Evidence, d Dedupe) *Scan {
	s := NewScan("", trigger, yara.PresetQuick, ev, d)
	s.owner = func(string) string { return `DOMAIN\a` }
	s.now = func() time.Time { return time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC) }
	return s
}

func result(path string, hits ...Hit) FileResult {
	return FileResult{Path: path, SHA256: sha, Size: 12, MTime: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Hits: hits}
}

func hit(rule string) Hit {
	return Hit{RulesetID: rsID, RulesetRevision: 3, Rule: rule, Namespace: "default", Tags: []string{"hacktool"},
		Meta: map[string]any{"severity": "high", "score": 80, "nested": map[string]any{"x": 1}}, StringIDs: []string{"$s1", "$s1", "not an id"}}
}

func TestMatches_FullPath(t *testing.T) {
	s := testScan(yara.TriggerOnDemand, yara.Evidence{PathMode: yara.PathModeFull}, nil)
	evs, err := s.Matches(result(`C:\Users\a\Downloads\x.EXE`, hit("Mimikatz")))
	if err != nil || len(evs) != 1 {
		t.Fatalf("events = %v, %v", evs, err)
	}
	m := evs[0].Match
	if *m.Path != `C:\Users\a\Downloads\x.EXE` || m.PathHash != nil || m.FileExt != "" {
		t.Errorf("path evidence: %v %v %q", m.Path, m.PathHash, m.FileExt)
	}
	if m.SHA256 != strings.ToLower(sha) || m.Owner != `DOMAIN\a` || m.ScanID != s.ID || m.Trigger != yara.TriggerOnDemand {
		t.Errorf("match = %+v", m)
	}
	if len(m.StringIDs) != 1 || m.StringIDs[0] != "$s1" {
		t.Errorf("string ids = %v", m.StringIDs)
	}
	if _, nested := m.Meta["nested"]; nested || m.Meta["score"] != int64(80) {
		t.Errorf("meta = %v", m.Meta)
	}
	if err := evs[0].Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMatches_HashedPath(t *testing.T) {
	s := testScan(yara.TriggerScheduled, yara.Evidence{PathMode: yara.PathModeHashed}, nil)
	evs, err := s.Matches(result(`C:\Users\A\Downloads\Invoice.PDF.exe`, hit("r")))
	if err != nil {
		t.Fatal(err)
	}
	m := evs[0].Match
	if m.Path != nil || *m.PathHash != HashPath(`c:\users\a\downloads\invoice.pdf.exe`) || m.FileExt != "exe" {
		t.Fatalf("hashed evidence: %v %v %q", m.Path, *m.PathHash, m.FileExt)
	}
	data, _ := json.Marshal(evs[0])
	if strings.Contains(strings.ToLower(string(data)), "invoice") {
		t.Fatalf("hashed mode leaked the path: %s", data)
	}
}

func TestMatches_LongPathIsHashed(t *testing.T) {
	s := testScan(yara.TriggerOnDemand, yara.Evidence{PathMode: yara.PathModeFull}, nil)
	long := "/" + strings.Repeat("d/", yara.MaxPathLen/2) + "x.sh"
	evs, err := s.Matches(result(long, hit("r")))
	if err != nil {
		t.Fatal(err)
	}
	if evs[0].Match.Path != nil || evs[0].Match.PathHash == nil || evs[0].Match.FileExt != "sh" {
		t.Fatalf("long path: %+v", evs[0].Match)
	}
}

func TestFileExt(t *testing.T) {
	for in, want := range map[string]string{
		`C:\a\b.TXT`: "txt", "/a/b.tar.gz": "gz", "/a.d/b": "", "/a/b.": "", "/a/.bashrc": "bashrc",
		"/a/b." + strings.Repeat("x", 40): strings.Repeat("x", 32),
	} {
		if got := FileExt(in); got != want {
			t.Errorf("FileExt(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatches_DedupeScheduledOnly(t *testing.T) {
	d := memDedupe{}
	r := result("/home/a/x", hit("r1"), hit("r2"))
	s1 := testScan(yara.TriggerScheduled, yara.Evidence{PathMode: yara.PathModeFull}, d)
	if evs, _ := s1.Matches(r); len(evs) != 2 {
		t.Fatalf("first scheduled scan: %d events", len(evs))
	}
	s2 := testScan(yara.TriggerScheduled, yara.Evidence{PathMode: yara.PathModeFull}, d)
	r.Hits = append(r.Hits, hit("r3"))
	evs, _ := s2.Matches(r)
	if len(evs) != 1 || evs[0].Match.Rule != "r3" {
		t.Fatalf("second scheduled scan: %+v", evs)
	}
	if sum := s2.SummaryBody(yara.ScanCompleted, 1, 0, 0); sum.Matches != 3 {
		t.Errorf("summary matches = %d, want every match found (3)", sum.Matches)
	}
	// On-demand scans always report.
	od := testScan(yara.TriggerOnDemand, yara.Evidence{PathMode: yara.PathModeFull}, d)
	if evs, _ := od.Matches(r); len(evs) != 3 {
		t.Fatalf("on-demand scan: %d events", len(evs))
	}
}

func TestMatches_CapAndTruncatedSummary(t *testing.T) {
	s := testScan(yara.TriggerOnDemand, yara.Evidence{PathMode: yara.PathModeFull}, nil)
	total := 0
	for i := range MaxMatchEventsPerScan + 10 {
		evs, err := s.Matches(result("/f"+strings.Repeat("x", i%7), hit("everything")))
		if err != nil {
			t.Fatal(err)
		}
		total += len(evs)
	}
	if total != MaxMatchEventsPerScan {
		t.Fatalf("%d events, want the cap %d", total, MaxMatchEventsPerScan)
	}
	ev := s.Summary(yara.ScanCompleted, 6000, 0, 0)
	if !ev.Summary.Truncated || ev.Summary.Matches != MaxMatchEventsPerScan+10 {
		t.Fatalf("summary = %+v", ev.Summary)
	}
	if err := ev.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestMatches_Rejects(t *testing.T) {
	s := testScan(yara.TriggerOnDemand, yara.Evidence{PathMode: yara.PathModeFull}, nil)
	if _, err := s.Matches(FileResult{Path: "/x", SHA256: "nope", Hits: []Hit{hit("r")}}); err == nil {
		t.Error("accepted a result without a hash")
	}
	if _, err := s.Matches(result("/x", Hit{Rule: ""})); err == nil {
		t.Error("accepted a hit without a rule")
	}
	if evs, err := s.Matches(result("/x")); err != nil || evs != nil {
		t.Errorf("no hits: %v, %v", evs, err)
	}
	// A ruleset id that isn't a UUID is left out rather than failing the batch.
	h := hit("r")
	h.RulesetID = "local"
	if evs, err := s.Matches(result("/x", h)); err != nil || evs[0].Match.RulesetID != "" {
		t.Errorf("bad ruleset id: %+v, %v", evs, err)
	}
}

func TestCleanMeta_SizeCap(t *testing.T) {
	meta := map[string]any{}
	for i := range 20 {
		meta[string(rune('a'+i))] = strings.Repeat("v", 400)
	}
	out := cleanMeta(meta)
	data, _ := json.Marshal(out)
	if len(data) > yara.MaxMetaBytes || len(out) == 0 {
		t.Fatalf("meta is %d bytes with %d keys", len(data), len(out))
	}
}

// A scan continued after a restart keeps its start time, counts and cap.
func TestScan_RestoreProgress(t *testing.T) {
	started := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	s := NewScan("", yara.TriggerScheduled, yara.PresetQuick, yara.Evidence{PathMode: yara.PathModeHashed}, nil)
	s.Restore(started, Progress{Found: 7, Sent: MaxMatchEventsPerScan, Truncated: true})
	if got := s.Progress(); got.Found != 7 || got.Sent != MaxMatchEventsPerScan || !got.Truncated {
		t.Fatalf("progress %+v", got)
	}
	sum := s.SummaryBody(yara.ScanCompleted, 1, 0, 0)
	if !sum.StartedAt.Equal(started) || sum.Matches != 7 || !sum.Truncated {
		t.Fatalf("summary %+v", sum)
	}
}
