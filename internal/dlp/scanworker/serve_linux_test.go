package scanworker

import (
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/dlp/detect"
	"sentinelgo/internal/dlp/filescan"
)

// The worker's serve loop in-process (without the sandbox, which would
// confine the test itself): policy, scans with a passed descriptor, and
// requests it can't answer.
func TestServe_InProcess(t *testing.T) {
	svc, child, err := socketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = svc.c.Close() }()
	worker, _, err := fileConn(child)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- serve(worker, "test") }()

	read := func() message {
		t.Helper()
		_ = svc.c.SetReadDeadline(time.Now().Add(10 * time.Second))
		m, f, err := svc.readMsg(maxFrameFromWorker)
		if err != nil {
			t.Fatal(err)
		}
		if f != nil {
			t.Error("the worker sent a descriptor")
			_ = f.Close()
		}
		return m
	}
	if m := read(); m.Type != typeReady || m.Sandbox != "test" {
		t.Fatalf("hello %+v", m)
	}
	scan := func(id uint64, content string) *filescan.Result {
		t.Helper()
		f, size := tempFile(t, content)
		if err := svc.writeMsg(message{Type: typeScan, ID: id, Size: size}, int(f.Fd())); err != nil { // #nosec G115 -- a descriptor
			t.Fatal(err)
		}
		m := read()
		if m.Type != typeResult || m.ID != id || m.Result == nil {
			t.Fatalf("reply %+v", m)
		}
		return m.Result
	}

	// Before any policy: nothing to scan with.
	if res := scan(1, "TOPSECRET"); res.Status != filescan.Unscannable(ReasonWorkerFailed) {
		t.Errorf("without policy: %q", res.Status)
	}
	if err := svc.writeMsg(message{Type: typePolicy, Bundle: []byte(bundle)}, -1); err != nil {
		t.Fatal(err)
	}
	if res := scan(2, "a TOPSECRET b"); res.Status != filescan.StatusScanned || len(res.Findings) != 1 || res.SHA256 == "" {
		t.Errorf("scan %+v", res)
	}
	// A scan without a descriptor fails cleanly.
	if err := svc.writeMsg(message{Type: typeScan, ID: 3, Size: 1}, -1); err != nil {
		t.Fatal(err)
	}
	if m := read(); m.Result == nil || m.Result.Status != filescan.Unscannable(ReasonWorkerFailed) {
		t.Errorf("no descriptor: %+v", m)
	}
	// A bad policy leaves the worker without one.
	if err := svc.writeMsg(message{Type: typePolicy, Bundle: []byte(`{"schema_version": 9}`)}, -1); err != nil {
		t.Fatal(err)
	}
	if res := scan(4, "TOPSECRET"); res.Status != filescan.Unscannable(ReasonWorkerFailed) {
		t.Errorf("after a bad policy: %q", res.Status)
	}
	// Unknown messages (with a descriptor) are ignored and the fd closed.
	f, _ := tempFile(t, "x")
	if err := svc.writeMsg(message{Type: "bogus"}, int(f.Fd())); err != nil { // #nosec G115 -- a descriptor
		t.Fatal(err)
	}
	if res := scan(5, "x"); res.Status != filescan.Unscannable(ReasonWorkerFailed) {
		t.Errorf("after an unknown message: %q", res.Status)
	}
	// Closing the socket ends the worker cleanly.
	_ = svc.c.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve didn't return after the socket closed")
	}
}

func TestReadMsg_Limits(t *testing.T) {
	a, child, err := socketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.c.Close() }()
	b, _, err := fileConn(child)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.c.Close() }()
	// A frame over the limit is refused.
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, 1<<30)
	if _, err := a.c.Write(hdr); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.readMsg(1024); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("oversized frame: %v", err)
	}
	// Garbage JSON is refused.
	binary.BigEndian.PutUint32(hdr, 3)
	if _, err := a.c.Write(append(hdr, "{{{"...)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.readMsg(1024); err == nil {
		t.Error("bad JSON accepted")
	}
	// takeFD with several descriptors keeps the first and closes the rest.
	if f, err := takeFD(nil); f != nil || err != nil {
		t.Errorf("empty oob: %v %v", f, err)
	}
}

func TestCapOffsets(t *testing.T) {
	many := make([][2]int, maxOffsets+5)
	r := filescan.Result{
		Findings: []detect.Finding{{Count: len(many), Offsets: many}},
		Entries:  []filescan.Entry{{Findings: []detect.Finding{{Count: len(many), Offsets: many}}}},
	}
	capOffsets(&r)
	if len(r.Findings[0].Offsets) != maxOffsets || len(r.Entries[0].Findings[0].Offsets) != maxOffsets || r.Findings[0].Count != len(many) {
		t.Errorf("offsets %d/%d, count %d", len(r.Findings[0].Offsets), len(r.Entries[0].Findings[0].Offsets), r.Findings[0].Count)
	}
}
