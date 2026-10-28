package events

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/dlp/detect"
)

func scan(t *testing.T, content string) (detect.Result, []detect.Finding) {
	t.Helper()
	e, errs := detect.New([]detect.Rule{{DetectorID: "custom.keywords", RuleID: "r1", Keywords: []string{"falcon-secret-42"}}}, 0)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	res := e.Scan(content)
	return res, res.Findings
}

func TestBuild_EvidenceModes(t *testing.T) {
	content := strings.Repeat("lorem ipsum ", 100) + "the code is falcon-secret-42 ok" + strings.Repeat(" dolor", 100)
	res, findings := scan(t, content)
	meta := Meta{Channel: "clipboard", User: `CORP\alice`, SessionID: "2", OccurredAt: time.Unix(1_700_000_000, 0)}

	for _, mode := range []string{"none", "masked", "full"} {
		t.Run(mode, func(t *testing.T) {
			ev := Build(meta, Match{PolicyID: "p1", PolicyVersion: "v1", Action: ActionBlocked, Severity: "high", EvidenceMode: mode}, res, findings, content)
			data, _ := json.Marshal(ev)
			if mode != "full" && strings.Contains(string(data), "falcon-secret-42") {
				t.Fatalf("raw match in %s-mode event: %s", mode, data)
			}
			if ev.ContentLength != len(content) || len(ev.ContentSHA256) != 64 || ev.RepeatCount != 1 {
				t.Errorf("event = %+v", ev)
			}
			if len(ev.Findings) != 1 || ev.Findings[0].Detector != "custom.keywords" || ev.Findings[0].SHA256 == "" {
				t.Errorf("findings = %+v", ev.Findings)
			}
			switch mode {
			case "none":
				if ev.Findings[0].Masked != "" || ev.Excerpt != "" {
					t.Errorf("none mode kept evidence: %+v", ev)
				}
			case "masked":
				if ev.Findings[0].Masked == "" || ev.Excerpt != "" {
					t.Errorf("masked mode: %+v", ev)
				}
			case "full":
				if !strings.Contains(ev.Excerpt, "falcon-secret-42") || len(ev.Excerpt) > maxExcerptBytes {
					t.Errorf("full mode excerpt = %q (%d bytes)", ev.Excerpt, len(ev.Excerpt))
				}
			}
		})
	}
}

func TestExcerpt_RuneBoundaries(t *testing.T) {
	content := strings.Repeat("é", 400) + "X" + strings.Repeat("é", 400)
	got := excerpt(content, [2]int{800, 801})
	if !strings.Contains(got, "X") || !strings.HasPrefix(got, "é") || !strings.HasSuffix(got, "é") {
		t.Errorf("excerpt split a rune or missed the match: %q…", got[:10])
	}
}

func TestNewID(t *testing.T) {
	re := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	seen := map[string]bool{}
	for range 100 {
		id := NewID()
		if !re.MatchString(id) || seen[id] {
			t.Fatalf("bad or repeated id %q", id)
		}
		seen[id] = true
	}
}

func TestDedupeKey(t *testing.T) {
	a := Event{ContentSHA256: "h", PolicyID: "p1"}
	if a.DedupeKey() == (Event{ContentSHA256: "h", PolicyID: "p2"}).DedupeKey() {
		t.Error("different policies share a dedupe key")
	}
}
