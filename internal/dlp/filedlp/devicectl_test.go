//go:build windows || darwin

package filedlp

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
)

func ctlVolume(src string, usb *events.USB) devVolume {
	return devVolume{Destination: Destination{Channel: policy.ChannelFileRemovable, Type: TypeRemovable,
		Mount: "/m/" + src, Source: src, USB: usb}}
}

const ctlBundle = `{"schema_version": 1, "version": "v1", "enabled": true,
  "modules": {"files": {"enabled": true, "channels": {"file.removable": true}, "audit_only": false,
    "copy_correlation": {"untrusted_devices": "read_only"}TRUSTED}},
  "policies": []}`

func TestDeviceCtl_Lifecycle(t *testing.T) {
	var calls []string
	fail := false
	sink := &recordingSink{}
	d := newDeviceCtl(sink, func(v devVolume, ro bool) error {
		calls = append(calls, v.Source+map[bool]string{true: ":ro", false: ":rw"}[ro])
		if fail {
			return errors.New("busy")
		}
		return nil
	}, func(string) { calls = append(calls, "release") })
	strict := compile(t, strings.Replace(ctlBundle, "TRUSTED", "", 1))
	usb := &events.USB{VendorID: "0951", ProductID: "1666"}
	a, b := ctlVolume("a", usb), ctlVolume("b", nil)
	got := func() string { s := strings.Join(calls, ","); calls = nil; return s }

	// A failing change is tried again on the next pass, and logged once.
	fail = true
	d.reconcile(strict, []devVolume{a}, false)
	d.reconcile(strict, []devVolume{a}, false)
	if g := got(); g != "release,a:ro,release,a:ro" || d.madeReadOnly("a") || len(sink.events()) != 0 {
		t.Fatalf("failing: %s", g)
	}
	fail = false
	d.reconcile(strict, []devVolume{a, b}, false)
	if !d.madeReadOnly("a") || !d.madeReadOnly("b") || len(sink.events()) != 2 {
		t.Fatalf("not applied: %s %d events", got(), len(sink.events()))
	}
	got()
	d.reconcile(strict, []devVolume{a, b}, false)
	if g := got(); g != "" || len(sink.events()) != 2 {
		t.Errorf("applied twice: %s", g)
	}

	// The device becomes trusted: writable again. b is unplugged: forgotten.
	trusted := compile(t, strings.Replace(ctlBundle, "TRUSTED", `, "trusted_devices": [{"vendor_id": "0951", "product_id": "1666"}]`, 1))
	d.reconcile(trusted, []devVolume{a}, false)
	if g := got(); g != "release,a:rw" || d.madeReadOnly("a") || d.madeReadOnly("b") {
		t.Errorf("trust/unplug: %s", g)
	}

	// The emergency switch and stop restore everything.
	d.reconcile(strict, []devVolume{b}, false)
	got()
	d.reconcile(strict, []devVolume{b}, true)
	if g := got(); g != "release,b:rw" {
		t.Errorf("emergency switch: %s", g)
	}
	d.reconcile(strict, []devVolume{b}, false)
	got()
	d.restore()
	if g := got(); g != "b:rw" || d.madeReadOnly("b") {
		t.Errorf("restore: %s", g)
	}
	// Plugged in again later: recorded again.
	n := len(sink.events())
	d.reconcile(strict, nil, false)
	d.reconcile(strict, []devVolume{b}, false)
	if len(sink.events()) != n+1 {
		t.Errorf("re-plug not recorded: %d → %d", n, len(sink.events()))
	}
	// A write-protected volume is left alone.
	ro := ctlVolume("c", nil)
	ro.ReadOnly = true
	got()
	d.reconcile(strict, []devVolume{b, ro}, false)
	if g := got(); strings.Contains(g, "c:") {
		t.Errorf("a read-only volume was changed: %s", g)
	}
}

func TestPendingSet(t *testing.T) {
	var dropped, unreadable atomic.Uint64
	p := newPendingSet(&dropped, &unreadable)
	now := time.Now()
	root := t.TempDir()
	recent := filepath.Join(root, "recent.txt")
	if err := os.WriteFile(recent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	p.add(fsChange{root: root}, now) // a rescan finds the recent file
	p.add(fsChange{root: root, path: filepath.Join(root, "busy.txt")}, now)
	p.add(fsChange{root: root, path: filepath.Join(root, "~WRL0001.tmp")}, now)
	if len(p.m) != 3 {
		t.Fatalf("pending %v", p.m)
	}
	queue := make(chan Request, 1)
	open := func(path string, _ time.Time) (Request, openStatus) {
		switch filepath.Base(path) {
		case "busy.txt":
			return Request{}, openRetry
		case "recent.txt":
			f, err := os.Open(path) // #nosec G304 -- the test's own file
			if err != nil {
				t.Fatal(err)
			}
			return Request{File: f, Path: path}, openOK
		}
		return Request{}, openSkip
	}
	// Not quiet yet: nothing opened.
	p.due(now, open, queue)
	if len(queue) != 0 || len(p.m) != 3 {
		t.Fatalf("opened too early: %d queued, %d pending", len(queue), len(p.m))
	}
	// Quiet: the recent file is queued, the busy one waits, the temp name
	// waits longer.
	p.due(now.Add(quietFor+time.Millisecond), open, queue)
	if len(queue) != 1 || len(p.m) != 2 {
		t.Fatalf("%d queued, %d pending", len(queue), len(p.m))
	}
	r := <-queue
	_ = r.File.Close()
	// Still busy after the give-up time: dropped as unreadable.
	p.due(now.Add(pendingGiveUp+tempQuietFor+time.Minute), open, queue)
	if len(p.m) != 0 || unreadable.Load() != 1 {
		t.Errorf("pending %v unreadable %d", p.m, unreadable.Load())
	}
	// A full queue drops (and closes) the file.
	full := make(chan Request)
	p.add(fsChange{root: root, path: recent}, now)
	p.due(now.Add(time.Minute), open, full)
	if dropped.Load() != 1 {
		t.Errorf("dropped %d", dropped.Load())
	}
	// Past maxPending, new files are dropped.
	for i := 0; i <= maxPending; i++ {
		p.addPath(filepath.Join(root, "f", string(rune('a'+i%26)), time.Duration(i).String()), now)
	}
	if dropped.Load() != 2 {
		t.Errorf("over the cap: dropped %d", dropped.Load())
	}
}
