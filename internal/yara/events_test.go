package yara

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

const evID = "0d9e8f7a-4444-4b6c-9d0e-0123456789ab"

func ptr[T any](v T) *T { return &v }

func sampleMatch() *Match {
	return &Match{
		ScanID: schID, Trigger: TriggerScheduled,
		RulesetID: rsID, RulesetRevision: 3,
		Rule: "Mimikatz_Generic", Namespace: "default",
		Tags: []string{"hacktool"}, Meta: map[string]any{"severity": "high", "score": 80.0, "fp": false},
		Path: ptr(`C:\Users\a\Downloads\x.exe`), SHA256: hash, Size: 1203,
		MTime: time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC), Owner: `DOMAIN\a`,
		StringIDs:  []string{"$s1", "$s2"},
		DetectedAt: time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC),
	}
}

func TestEvent_MatchShape(t *testing.T) {
	ev := Event{EventID: evID, Match: sampleMatch()}
	if err := ev.Validate(); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"event_id": evID, "kind": "match", "scan_id": schID, "trigger": "scheduled",
		"ruleset_id": rsID, "ruleset_revision": 3.0, "rule": "Mimikatz_Generic", "namespace": "default",
		"tags": []any{"hacktool"}, "meta": map[string]any{"severity": "high", "score": 80.0, "fp": false},
		"path": `C:\Users\a\Downloads\x.exe`, "path_hash": nil, "sha256": hash, "size": 1203.0,
		"mtime": "2026-11-01T08:00:00Z", "owner": `DOMAIN\a`, "string_ids": []any{"$s1", "$s2"},
		"detected_at": "2026-11-10T09:00:00Z",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("match JSON\n%s\nwant\n%v", data, want)
	}
	var back Event
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, ev) {
		t.Fatalf("round trip:\n%+v\nwant\n%+v", back.Match, ev.Match)
	}
}

func TestEvent_HashedPath(t *testing.T) {
	m := sampleMatch()
	m.Path, m.PathHash, m.FileExt = nil, ptr(hash), "exe"
	data, err := json.Marshal(Event{EventID: evID, Match: m})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"path":null`) || !strings.Contains(string(data), `"file_ext":"exe"`) {
		t.Fatalf("hashed match = %s", data)
	}
	if err := (Event{EventID: evID, Match: m}).Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestEvent_SummaryShape(t *testing.T) {
	ev := Event{EventID: evID, Summary: &ScanSummary{
		ScanID: schID, Trigger: TriggerOnDemand, Preset: PresetFull, State: ScanPartial,
		StartedAt: time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC), FilesScanned: 5, Truncated: true,
	}}
	if err := ev.Validate(); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"event_id": evID, "kind": "scan_summary", "scan_id": schID, "trigger": "on_demand", "preset": "full",
		"started_at": "2026-11-10T09:00:00Z", "state": "partial",
		"files_scanned": 5.0, "files_skipped": 0.0, "errors": 0.0, "matches": 0.0, "truncated": true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("summary JSON\n%s\nwant\n%v", data, want)
	}
	var back Event
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, ev) {
		t.Fatalf("round trip:\n%+v\nwant\n%+v", back.Summary, ev.Summary)
	}
}

func TestEvent_NeedsExactlyOneBody(t *testing.T) {
	for _, ev := range []Event{{EventID: evID}, {EventID: evID, Match: sampleMatch(), Summary: &ScanSummary{}}} {
		if _, err := json.Marshal(ev); err == nil {
			t.Errorf("marshalled %+v", ev)
		}
		if err := ev.Validate(); !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("Validate = %v", err)
		}
	}
	var ev Event
	if err := json.Unmarshal([]byte(`{"event_id":"x","kind":"content"}`), &ev); !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("unknown kind: %v", err)
	}
}

func TestMatch_ValidateRejects(t *testing.T) {
	cases := map[string]func(m *Match){
		"scan id":        func(m *Match) { m.ScanID = "x" },
		"trigger":        func(m *Match) { m.Trigger = "manual" },
		"ruleset id":     func(m *Match) { m.RulesetID = "x" },
		"revision":       func(m *Match) { m.RulesetRevision = -1 },
		"no rule":        func(m *Match) { m.Rule = "" },
		"long rule":      func(m *Match) { m.Rule = strings.Repeat("r", MaxRuleLen+1) },
		"long namespace": func(m *Match) { m.Namespace = strings.Repeat("n", MaxRuleLen+1) },
		"many tags":      func(m *Match) { m.Tags = make([]string, MaxTags+1) },
		"empty tag":      func(m *Match) { m.Tags = []string{""} },
		"long tag":       func(m *Match) { m.Tags = []string{strings.Repeat("t", MaxTagLen+1)} },
		"meta object":    func(m *Match) { m.Meta = map[string]any{"x": map[string]any{}} },
		"meta array":     func(m *Match) { m.Meta = map[string]any{"x": []any{1}} },
		"meta null":      func(m *Match) { m.Meta = map[string]any{"x": nil} },
		"meta too big":   func(m *Match) { m.Meta = map[string]any{"x": strings.Repeat("m", MaxMetaBytes)} },
		"sha":            func(m *Match) { m.SHA256 = "abc" },
		"size":           func(m *Match) { m.Size = -1 },
		"owner":          func(m *Match) { m.Owner = strings.Repeat("o", MaxOwnerLen+1) },
		"ext":            func(m *Match) { m.FileExt = strings.Repeat("e", MaxFileExtLen+1) },
		"string id":      func(m *Match) { m.StringIDs = []string{"s1"} },
		"string id text": func(m *Match) { m.StringIDs = []string{"$ matched text"} },
		"many strings":   func(m *Match) { m.StringIDs = make([]string, MaxStringIDs+1) },
		"no detected_at": func(m *Match) { m.DetectedAt = time.Time{} },
		"no path":        func(m *Match) { m.Path = nil },
		"empty path":     func(m *Match) { m.Path = ptr("") },
		"long path":      func(m *Match) { m.Path = ptr(strings.Repeat("p", MaxPathLen+1)) },
		"path hash":      func(m *Match) { m.Path, m.PathHash = nil, ptr("abc") },
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			m := sampleMatch()
			fn(m)
			if err := (Event{EventID: evID, Match: m}).Validate(); !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("Validate = %v, want ErrInvalidEvent", err)
			}
		})
	}
	if err := (Event{EventID: "x", Match: sampleMatch()}).Validate(); !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("bad event_id: %v", err)
	}
}

func TestMatch_OptionalFieldsMayBeEmpty(t *testing.T) {
	m := sampleMatch()
	m.RulesetID, m.Namespace, m.Tags, m.Meta, m.Owner, m.StringIDs, m.MTime = "", "", nil, nil, "", nil, time.Time{}
	if err := (Event{EventID: evID, Match: m}).Validate(); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(Event{EventID: evID, Match: m})
	for _, key := range []string{`"ruleset_id"`, `"owner"`, `"mtime"`} {
		if strings.Contains(string(data), key) {
			t.Errorf("%s sent while empty: %s", key, data)
		}
	}
}

func TestScanSummary_ValidateRejects(t *testing.T) {
	ok := ScanSummary{ScanID: schID, Trigger: TriggerScheduled, State: ScanCompleted}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, fn := range map[string]func(s *ScanSummary){
		"scan id": func(s *ScanSummary) { s.ScanID = "" },
		"trigger": func(s *ScanSummary) { s.Trigger = "" },
		"state":   func(s *ScanSummary) { s.State = "running" },
		"preset":  func(s *ScanSummary) { s.Preset = "deep" },
		"count":   func(s *ScanSummary) { s.Errors = -1 },
	} {
		s := ok
		fn(&s)
		if err := s.Validate(); !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("%s: Validate = %v", name, err)
		}
	}
}
