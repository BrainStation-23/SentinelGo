package collector

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// syslogLines builds one syslog line per hour for the given number of days,
// ending now, in the local zone (syslog lines carry no year or zone).
func syslogLines(days int, now time.Time) (string, []time.Time) {
	var b strings.Builder
	var times []time.Time
	for h := days * 24; h >= 0; h-- {
		ts := now.Add(-time.Duration(h) * time.Hour).Truncate(time.Second)
		times = append(times, ts)
		fmt.Fprintf(&b, "%s host sshd[1]: line %d\n", ts.Format("Jan _2 15:04:05"), h)
	}
	return b.String(), times
}

// A first run on a file holding 30 days of syslog starts at the first line
// within the window (#437).
func TestFirstRunOffset_StartsAtWindow(t *testing.T) {
	now := time.Now()
	content, _ := syslogLines(30, now)
	cutoff := now.Add(-3 * 24 * time.Hour)

	off, err := firstRunOffset(strings.NewReader(content), int64(len(content)), cutoff, parseSyslogTimestamp)
	if err != nil {
		t.Fatalf("firstRunOffset: %v", err)
	}
	rest := content[off:]
	lines := strings.Split(strings.TrimRight(rest, "\n"), "\n")
	if len(lines) < 70 || len(lines) > 74 {
		t.Errorf("read %d lines after the start, want about 72 (3 days, one per hour)", len(lines))
	}
	for _, l := range lines {
		if ts := parseSyslogTimestamp(l); ts.Before(cutoff) {
			t.Fatalf("line %q is older than the cutoff %s", l, cutoff)
		}
	}
	if off > 0 && content[off-1] != '\n' {
		t.Errorf("offset %d is not at a line start", off)
	}
}

// Nothing in the window: start at the end, so only new lines are read.
func TestFirstRunOffset_NothingInWindow(t *testing.T) {
	old := time.Now().Add(-10 * 24 * time.Hour)
	content := old.Format("Jan _2 15:04:05") + " host x: old\n"
	off, err := firstRunOffset(strings.NewReader(content), int64(len(content)), time.Now().Add(-time.Hour), parseSyslogTimestamp)
	if err != nil || off != int64(len(content)) {
		t.Errorf("offset = %d, %v; want %d (end of file)", off, err, len(content))
	}
}

// Unparseable lines don't decide where reading starts.
func TestFirstRunOffset_SkipsUnparseableLines(t *testing.T) {
	recent := time.Now().Add(-time.Minute).Format("Jan _2 15:04:05")
	content := "garbage line\n" + recent + " host x: new\n"
	off, err := firstRunOffset(strings.NewReader(content), int64(len(content)), time.Now().Add(-time.Hour), parseSyslogTimestamp)
	if err != nil || off != int64(len("garbage line\n")) {
		t.Errorf("offset = %d, %v; want %d", off, err, len("garbage line\n"))
	}
}

// A file bigger than the tail bound starts at a line boundary inside the tail.
func TestFirstRunOffset_LargeFileStartsInTail(t *testing.T) {
	recent := time.Now().Add(-time.Minute).Format("Jan _2 15:04:05") + " host x: new\n"
	pad := strings.Repeat("x", 99) + "\n" // unparseable
	var b strings.Builder
	for b.Len() < firstRunTailBytes+1000 {
		b.WriteString(pad)
	}
	b.WriteString(recent)
	content := b.String()
	off, err := firstRunOffset(strings.NewReader(content), int64(len(content)), time.Now().Add(-time.Hour), parseSyslogTimestamp)
	if err != nil {
		t.Fatalf("firstRunOffset: %v", err)
	}
	if got := content[off:]; got != recent {
		t.Errorf("read %q, want only the recent line", got)
	}
}
