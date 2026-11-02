package filedlp

import (
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sentinelgo/internal/dlp/detect"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/filescan"
	"sentinelgo/internal/dlp/policy"
	"sentinelgo/internal/dlp/scanworker"
)

type recordingSink struct {
	mu  sync.Mutex
	evs []events.Event
}

func (r *recordingSink) Emit(ev events.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, ev)
}

func (r *recordingSink) events() []events.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]events.Event(nil), r.evs...)
}

// fakeScanner returns a fixed result and counts calls.
type fakeScanner struct {
	res   filescan.Result
	calls atomic.Int32
}

func (f *fakeScanner) Scan(context.Context, *os.File, int64, time.Duration) filescan.Result {
	f.calls.Add(1)
	return f.res
}

func compile(t *testing.T, bundle string) *policy.Compiled {
	t.Helper()
	b, err := policy.Decode([]byte(bundle))
	if err != nil {
		t.Fatal(err)
	}
	c := policy.Compile(b)
	if len(c.CompileErrors) > 0 {
		t.Fatalf("compile: %v", c.CompileErrors)
	}
	return c
}

func testBundle(evidence, files, exceptions string) string {
	if files == "" {
		files = `"enabled": true, "channels": {"file.removable": true, "file.network_share": true}`
	}
	if exceptions == "" {
		exceptions = "{}"
	}
	return `{"schema_version": 1, "version": "v1", "enabled": true, "evidence_mode": "` + evidence + `",
	  "modules": {"files": {` + files + `}},
	  "policies": [{"id": "p1", "name": "Cards", "severity": "high", "channels": ["file.removable", "file.network_share"],
	    "action": "block", "detectors": [{"id": "pii.credit_card", "rule_id": "r1", "min_count": 1}],
	    "exceptions": ` + exceptions + `}]}`
}

func cardFinding() detect.Finding {
	return detect.Finding{DetectorID: "pii.credit_card", Count: 1, Masked: "4111***1111", SHA256: "abc", Offsets: [][2]int{{0, 19}}}
}

func usbRequest() Request {
	return Request{
		Path: "/media/alice/KINGSTON/Users/alice/export.XLSX",
		Dest: Destination{Channel: policy.ChannelFileRemovable, Type: TypeRemovable, Mount: "/media/alice/KINGSTON",
			VolumeLabel: "KINGSTON", USB: &events.USB{VendorID: "0951", ProductID: "1666", Serial: "S1"}},
		Proc:  Process{PID: 42, Name: "nautilus", Exe: "/usr/bin/nautilus", UID: "1000", User: "alice"},
		Ident: Identity{Dev: 8, Ino: 99, Size: 1234, ModTime: 1, ChangeTime: 2},
		At:    time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC),
	}
}

func TestDecider_MatchRecordsMonitoredEvent(t *testing.T) {
	sink := &recordingSink{}
	sc := &fakeScanner{res: filescan.Result{Status: filescan.StatusScanned, DetectedType: "ooxml.xlsx", SHA256: "deadbeef",
		Findings: []detect.Finding{cardFinding()}, Duration: 120 * time.Millisecond}}
	d := NewDecider(sc, sink)
	d.Apply(compile(t, testBundle("masked", "", "")))
	d.Handle(context.Background(), usbRequest())

	evs := sink.events()
	if len(evs) != 1 {
		t.Fatalf("events: %+v", evs)
	}
	ev := evs[0]
	// Audit-only: the policy says block, the event says monitored.
	if ev.Action != events.ActionMonitored || ev.Channel != policy.ChannelFileRemovable || ev.PolicyID != "p1" || ev.Severity != "high" {
		t.Errorf("event %+v", ev)
	}
	if ev.User != "alice" || ev.SessionID != "1000" || ev.ContentSHA256 != "deadbeef" || ev.ContentLength != 1234 {
		t.Errorf("identity fields %+v", ev)
	}
	if ev.File == nil || ev.File.Name == nil || *ev.File.Name != "export.XLSX" || ev.File.Ext != "xlsx" || ev.File.DetectedType != "ooxml.xlsx" {
		t.Errorf("file %+v", ev.File)
	}
	if ev.Destination == nil || ev.Destination.Type != TypeRemovable || ev.Destination.VolumeLabel != "KINGSTON" || ev.Destination.USB.Serial != "S1" {
		t.Errorf("destination %+v", ev.Destination)
	}
	if ev.Process == nil || ev.Process.Name != "nautilus" || ev.Scan == nil || ev.Scan.VerdictSource != "scan" || ev.Scan.DurationMs != 120 {
		t.Errorf("process/scan %+v %+v", ev.Process, ev.Scan)
	}
	if len(ev.Findings) != 1 || ev.Findings[0].Masked != "4111***1111" {
		t.Errorf("findings %+v", ev.Findings)
	}
	if s := d.Stats(); s.Scans != 1 || s.Events != 1 {
		t.Errorf("stats %+v", s)
	}
}

func TestDecider_EvidenceModes(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		wantName *string
		masked   bool
	}{
		{"none", nil, false},
		{"masked", ptr("export.XLSX"), true},
		{"full", ptr("/media/alice/KINGSTON/Users/alice/export.XLSX"), true},
	} {
		sink := &recordingSink{}
		d := NewDecider(&fakeScanner{res: filescan.Result{Status: filescan.StatusScanned, Findings: []detect.Finding{cardFinding()}}}, sink)
		d.Apply(compile(t, testBundle(tc.mode, "", "")))
		d.Handle(context.Background(), usbRequest())
		ev := sink.events()[0]
		if (ev.File.Name == nil) != (tc.wantName == nil) || ev.File.Name != nil && *ev.File.Name != *tc.wantName {
			t.Errorf("%s: name %v", tc.mode, ev.File.Name)
		}
		if (ev.Findings[0].Masked != "") != tc.masked {
			t.Errorf("%s: masked %q", tc.mode, ev.Findings[0].Masked)
		}
	}
}

func ptr(s string) *string { return &s }

func TestDecider_NothingToDo(t *testing.T) {
	match := filescan.Result{Status: filescan.StatusScanned, Findings: []detect.Finding{cardFinding()}}
	for _, tc := range []struct {
		name, files, exceptions string
		req                     func(Request) Request
	}{
		{"channel off", `"enabled": true, "channels": {"file.network_share": true}`, "", nil},
		{"module off", `"enabled": false, "channels": {"file.removable": true}`, "", nil},
		{"empty file", "", "", func(r Request) Request { r.Ident.Size = 0; return r }},
		{"excepted app by path", "", `{"apps": ["/usr/bin/nautilus"]}`, nil},
		{"excepted app by name", "", `{"apps": [{"name": "Nautilus"}]}`, nil},
		{"trusted device", "", `{"trusted_devices": [{"vendor_id": "0951", "product_id": "1666"}]}`, nil},
		{"trusted device with serial", "", `{"trusted_devices": [{"vendor_id": "0951", "product_id": "1666", "serial": "S1"}]}`, nil},
	} {
		sink := &recordingSink{}
		sc := &fakeScanner{res: match}
		d := NewDecider(sc, sink)
		d.Apply(compile(t, testBundle("masked", tc.files, tc.exceptions)))
		r := usbRequest()
		if tc.req != nil {
			r = tc.req(r)
		}
		d.Handle(context.Background(), r)
		if len(sink.events()) != 0 || sc.calls.Load() != 0 {
			t.Errorf("%s: %d events, %d scans", tc.name, len(sink.events()), sc.calls.Load())
		}
	}
	// A device with another serial isn't trusted.
	sink := &recordingSink{}
	d := NewDecider(&fakeScanner{res: match}, sink)
	d.Apply(compile(t, testBundle("masked", "", `{"trusted_devices": [{"vendor_id": "0951", "product_id": "1666", "serial": "OTHER"}]}`)))
	d.Handle(context.Background(), usbRequest())
	if len(sink.events()) != 1 {
		t.Error("an untrusted serial was trusted")
	}
	// No policy applied: nothing.
	d = NewDecider(&fakeScanner{res: match}, sink)
	d.Handle(context.Background(), usbRequest())
}

func TestDecider_TrustedShare(t *testing.T) {
	dest := Destination{Channel: policy.ChannelFileNetworkShare, Type: TypeNetworkShare, ShareHost: "corp-fs", Source: "//corp-fs/finance"}
	for _, tc := range []struct {
		trusted []string
		want    bool
	}{
		{[]string{"corp-fs"}, true},
		{[]string{"CORP-FS"}, true},
		{[]string{`\\corp-fs\finance`}, true},
		{[]string{"//corp-fs/finance/"}, true},
		{[]string{"//corp-fs/hr"}, false},
		{[]string{"other"}, false},
		{nil, false},
	} {
		if got := TrustedShare(tc.trusted, dest); got != tc.want {
			t.Errorf("TrustedShare(%v) = %v", tc.trusted, got)
		}
	}
	if TrustedShare([]string{"corp-fs"}, Destination{Type: TypeRemovable, ShareHost: "corp-fs"}) {
		t.Error("a removable drive matched a trusted share")
	}
}

// Unscannable and timed-out files are recorded only when the policy asks
// (fail-open by default).
func TestDecider_FailModes(t *testing.T) {
	for _, tc := range []struct {
		name, files, status string
		want                int
	}{
		{"unscannable, default allow", "", filescan.Unscannable(filescan.ReasonPasswordProtected), 0},
		{"unscannable, monitor", `"enabled": true, "channels": {"file.removable": true}, "on_unscannable": "monitor"`, filescan.Unscannable(filescan.ReasonPasswordProtected), 1},
		{"unscannable, block", `"enabled": true, "channels": {"file.removable": true}, "on_unscannable": "block"`, filescan.Unscannable(filescan.ReasonTooLarge), 1},
		{"timeout, default allow", "", filescan.StatusTimeout, 0},
		{"timeout, block", `"enabled": true, "channels": {"file.removable": true}, "on_timeout": "block"`, filescan.StatusTimeout, 1},
		{"clean", `"enabled": true, "channels": {"file.removable": true}, "on_unscannable": "block", "on_timeout": "block"`, filescan.StatusScanned, 0},
	} {
		sink := &recordingSink{}
		d := NewDecider(&fakeScanner{res: filescan.Result{Status: tc.status}}, sink)
		d.Apply(compile(t, testBundle("masked", tc.files, "")))
		d.Handle(context.Background(), usbRequest())
		evs := sink.events()
		if len(evs) != tc.want {
			t.Errorf("%s: %d events", tc.name, len(evs))
			continue
		}
		if tc.want == 1 && (evs[0].Scan.Status != tc.status || len(evs[0].Findings) != 0 || evs[0].Action != events.ActionMonitored) {
			t.Errorf("%s: event %+v", tc.name, evs[0])
		}
	}
}

// The same version of a file is scanned once per policy version.
func TestDecider_Cache(t *testing.T) {
	sink := &recordingSink{}
	sc := &fakeScanner{res: filescan.Result{Status: filescan.StatusScanned, Findings: []detect.Finding{cardFinding()}}}
	d := NewDecider(sc, sink)
	d.Apply(compile(t, testBundle("masked", "", "")))
	r := usbRequest()
	d.Handle(context.Background(), r)
	d.Handle(context.Background(), r)
	if sc.calls.Load() != 1 || len(sink.events()) != 2 || sink.events()[1].Scan.VerdictSource != "cache" {
		t.Errorf("scans %d, events %+v", sc.calls.Load(), sink.events())
	}
	r.Ident.ModTime = 5 // edited
	d.Handle(context.Background(), r)
	if sc.calls.Load() != 2 {
		t.Errorf("edited file not rescanned (%d scans)", sc.calls.Load())
	}
	d.Apply(compile(t, strings.Replace(testBundle("masked", "", ""), `"v1"`, `"v2"`, 1)))
	d.Handle(context.Background(), r)
	if sc.calls.Load() != 3 {
		t.Errorf("new policy reused an old verdict (%d scans)", sc.calls.Load())
	}
	d.Invalidate(r.Ident)
	d.Handle(context.Background(), r)
	if sc.calls.Load() != 4 {
		t.Errorf("invalidated file not rescanned (%d scans)", sc.calls.Load())
	}
	if s := d.Stats(); s.Cached != 1 || s.Scans != 4 {
		t.Errorf("stats %+v", s)
	}
}

// An archive matches when one of its entries does.
func TestDecider_ArchiveEntry(t *testing.T) {
	sink := &recordingSink{}
	sc := &fakeScanner{res: filescan.Result{Status: filescan.StatusScanned, DetectedType: "archive.zip",
		Entries: []filescan.Entry{{Name: "a.txt", Status: filescan.StatusScanned}, {Name: "b/cards.csv", Status: filescan.StatusScanned, Findings: []detect.Finding{cardFinding()}}}}}
	d := NewDecider(sc, sink)
	d.Apply(compile(t, testBundle("masked", "", "")))
	d.Handle(context.Background(), usbRequest())
	if evs := sink.events(); len(evs) != 1 || len(evs[0].Findings) != 1 {
		t.Errorf("events %+v", evs)
	}
}

func TestCapabilities(t *testing.T) {
	c := compile(t, testBundle("masked", `"enabled": true, "channels": {"file.removable": true, "file.upload": true}`, ""))
	caps := channelCapabilities(c, map[string]bool{policy.ChannelFileRemovable: true}, stateRunning, workersOK)
	if caps[policy.ChannelFileRemovable] != "supported" || caps[policy.ChannelFileUpload] != "unsupported:not_implemented" || len(caps) != 2 {
		t.Errorf("caps %v", caps)
	}
	for state, want := range map[string]string{
		stateLocalOff:                      "unsupported:disabled_locally",
		stateStopped:                       "unsupported:not_running",
		"unavailable:fanotify_unavailable": "unsupported:fanotify_unavailable",
	} {
		if got := capability(state, workersOK); got != want {
			t.Errorf("capability(%s) = %s", state, got)
		}
	}
	if got := capability(stateRunning, workersDisabled); got != "unsupported:scan_worker_failed" {
		t.Errorf("crash loop: %s", got)
	}
	off := compile(t, testBundle("masked", `"enabled": false`, ""))
	if channelCapabilities(off, map[string]bool{policy.ChannelFileRemovable: true}, stateRunning, workersOK) != nil {
		t.Error("capabilities reported with the files module off")
	}
	if !wants(c.Modules.Files, map[string]bool{policy.ChannelFileRemovable: true}) || wants(c.Modules.Files, map[string]bool{policy.ChannelFileNetworkShare: true}) {
		t.Error("wants")
	}
}

var (
	workersOK       = scanworker.Health{Workers: 1}
	workersDisabled = scanworker.Health{Disabled: true}
)

// A policy's file_filters narrow it by size (before reading the file) and by
// type (the file's extension or detected type, and each archive entry's).
func TestDecider_FileFilters(t *testing.T) {
	bundleWith := func(filters string) string {
		return `{"schema_version": 1, "version": "v1", "enabled": true, "evidence_mode": "masked",
		  "modules": {"files": {"enabled": true, "channels": {"file.removable": true}, "on_unscannable": "monitor"}},
		  "policies": [{"id": "p1", "name": "Cards", "channels": ["file.removable"], "action": "monitor",
		    "detectors": [{"id": "pii.credit_card", "rule_id": "r1", "min_count": 1}], "file_filters": ` + filters + `}]}`
	}
	match := filescan.Result{Status: filescan.StatusScanned, DetectedType: "ooxml.xlsx", Findings: []detect.Finding{cardFinding()}}
	for _, tc := range []struct {
		name, filters string
		res           filescan.Result
		path          string
		events, scans int
	}{
		{"too big: not even read", `{"max_bytes": 100}`, match, "", 0, 0},
		{"too small: not even read", `{"min_bytes": 5000}`, match, "", 0, 0},
		{"in range", `{"min_bytes": 1000, "max_bytes": 2000}`, match, "", 1, 1},
		{"type by extension", `{"types": ["xlsx"]}`, match, "", 1, 1},
		{"renamed, type by content", `{"types": ["xlsx"]}`, match, "/media/alice/KINGSTON/holiday.jpg", 1, 1},
		{"other type", `{"types": ["pdf"]}`, match, "", 0, 1},
		{"other type, unscannable", `{"types": ["pdf"]}`, filescan.Result{Status: filescan.Unscannable(filescan.ReasonCorrupt), DetectedType: "ole.doc"}, "/media/x/a.doc", 0, 1},
		{"entry in a zip", `{"types": ["xlsx"]}`, filescan.Result{Status: filescan.StatusScanned, DetectedType: "archive.zip",
			Entries: []filescan.Entry{{Name: "q3/cards.xlsx", DetectedType: "ooxml.xlsx", Status: filescan.StatusScanned, Findings: []detect.Finding{cardFinding()}}}}, "/media/x/a.zip", 1, 1},
		{"entry of another type", `{"types": ["pdf"]}`, filescan.Result{Status: filescan.StatusScanned, DetectedType: "archive.zip",
			Entries: []filescan.Entry{{Name: "cards.txt", DetectedType: "text.utf8", Status: filescan.StatusScanned, Findings: []detect.Finding{cardFinding()}}}}, "/media/x/a.zip", 0, 1},
	} {
		sink := &recordingSink{}
		sc := &fakeScanner{res: tc.res}
		d := NewDecider(sc, sink)
		d.Apply(compile(t, bundleWith(tc.filters)))
		r := usbRequest()
		if tc.path != "" {
			r.Path = tc.path
		}
		d.Handle(context.Background(), r)
		if n := len(sink.events()); n != tc.events || int(sc.calls.Load()) != tc.scans {
			t.Errorf("%s: %d events, %d scans; want %d, %d", tc.name, n, sc.calls.Load(), tc.events, tc.scans)
		}
	}
}
