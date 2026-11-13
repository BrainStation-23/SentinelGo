package filedlp

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
)

type tallyNext struct{ got []events.Event }

func (r *tallyNext) Emit(ev events.Event) { r.got = append(r.got, ev) }

func findings(ids ...string) []events.Finding {
	out := make([]events.Finding, 0, len(ids))
	for _, id := range ids {
		out = append(out, events.Finding{Detector: id, Count: 1})
	}
	return out
}

func TestTally_CountsPerChannelAndPassesOn(t *testing.T) {
	next := &tallyNext{}
	since := time.Date(2026, 11, 13, 8, 0, 0, 0, time.FixedZone("x", 3600))
	tl := NewTally(next, since)

	tl.Emit(events.Event{Channel: policy.ChannelFileRemovable, Action: events.ActionMonitored, WouldHave: events.ActionQuarantined,
		Findings: findings("aws_key", "aws_key", "email")})
	tl.Emit(events.Event{Channel: policy.ChannelFileRemovable, Action: events.ActionQuarantined, Findings: findings("aws_key")})
	tl.Emit(events.Event{Channel: policy.ChannelFileRemovable, Action: events.ActionMonitored, RepeatCount: 3})
	tl.Emit(events.Event{Channel: policy.ChannelFileUpload, Action: events.ActionMonitored, WouldHave: events.NetworkBlocked})
	tl.Emit(events.Event{Channel: policy.ChannelFileCloudSync, Action: events.ActionDeleted})
	tl.Emit(events.Event{Channel: policy.ChannelClipboard, Action: events.ActionBlocked}) // not a file channel

	if len(next.got) != 6 {
		t.Fatalf("passed on %d events, want all 6", len(next.got))
	}
	s := tl.Summary()
	if !s.Since.Equal(since) || s.Since.Location() != time.UTC {
		t.Errorf("since %v, want %v in UTC", s.Since, since)
	}
	if _, ok := s.Channels[policy.ChannelClipboard]; ok {
		t.Error("the clipboard was counted")
	}
	rem := s.Channels[policy.ChannelFileRemovable]
	if rem.Events != 5 || rem.Actions[events.ActionMonitored] != 4 || rem.Actions[events.ActionQuarantined] != 1 {
		t.Errorf("removable events/actions: %+v", rem)
	}
	if rem.WouldHave[events.ActionQuarantined] != 1 || rem.Remediated != 1 {
		t.Errorf("removable would_have/remediated: %+v", rem)
	}
	if rem.Detectors["aws_key"] != 2 || rem.Detectors["email"] != 1 {
		t.Errorf("detectors (once per event): %v", rem.Detectors)
	}
	if up := s.Channels[policy.ChannelFileUpload]; up.WouldHave[events.NetworkBlocked] != 1 || up.Remediated != 0 {
		t.Errorf("upload: %+v", up)
	}
	if cs := s.Channels[policy.ChannelFileCloudSync]; cs.Remediated != 1 {
		t.Errorf("cloud sync: %+v", cs)
	}
}

func TestTally_SummaryIsACopy(t *testing.T) {
	tl := NewTally(nil, time.Now())
	tl.Emit(events.Event{Channel: policy.ChannelFileRemovable, Action: events.ActionMonitored})
	s := tl.Summary()
	s.Channels[policy.ChannelFileRemovable].Actions[events.ActionMonitored] = 99
	if got := tl.Summary().Channels[policy.ChannelFileRemovable].Actions[events.ActionMonitored]; got != 1 {
		t.Fatalf("a caller changed the tally: %d", got)
	}
}

func TestTally_DetectorCap(t *testing.T) {
	tl := NewTally(nil, time.Now())
	for i := 0; i < maxSummaryDetectors+5; i++ {
		tl.Emit(events.Event{Channel: policy.ChannelFileRemovable, Action: events.ActionMonitored, Findings: findings(fmt.Sprintf("d%03d", i))})
	}
	tl.Emit(events.Event{Channel: policy.ChannelFileRemovable, Action: events.ActionMonitored, Findings: findings("d000")}) // known id still counts
	c := tl.Summary().Channels[policy.ChannelFileRemovable]
	if len(c.Detectors) != maxSummaryDetectors || c.DetectorsOther != 5 || c.Detectors["d000"] != 2 {
		t.Fatalf("detectors %d, other %d, d000 %d", len(c.Detectors), c.DetectorsOther, c.Detectors["d000"])
	}
}

func TestSummary_JSONShape(t *testing.T) {
	tl := NewTally(nil, time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC))
	tl.Emit(events.Event{Channel: policy.ChannelFileRemovable, Action: events.ActionMonitored, WouldHave: events.ActionBlocked,
		Findings: findings("aws_key")})
	data, err := json.Marshal(Health{State: "running", Summary: tl.Summary()})
	if err != nil {
		t.Fatal(err)
	}
	want := `"summary":{"since":"2026-11-13T00:00:00Z","channels":{"file.removable":{"events":1,"actions":{"monitored":1},` +
		`"would_have":{"blocked":1},"remediated":0,"detectors":{"aws_key":1}}}}`
	if !strings.Contains(string(data), want) {
		t.Fatalf("got %s\nwant it to contain %s", data, want)
	}
}

// The status stays far under the server's 64 KB with every channel full.
func TestSummary_SizeBound(t *testing.T) {
	tl := NewTally(nil, time.Now())
	for _, ch := range policy.FileChannels {
		for i := 0; i < maxSummaryDetectors+10; i++ {
			tl.Emit(events.Event{Channel: ch, Action: events.ActionMonitored, WouldHave: events.ActionQuarantined,
				Findings: findings(fmt.Sprintf("a_rather_long_custom_detector_identifier_%03d", i))})
		}
	}
	data, _ := json.Marshal(tl.Summary())
	if len(data) > 16<<10 {
		t.Fatalf("summary is %d bytes", len(data))
	}
}
