package clipboard

import (
	"context"
	"testing"
	"time"

	"github.com/ebitengine/purego/objc"

	"sentinelgo/internal/dlp/events"
)

// Runs in CI on macOS (no -short gate): the AppKit calls work without cgo,
// reading only the change counter and types, never the user's content.
func TestDarwinPasteboardReachable(t *testing.T) {
	c := New().Supported()
	if !c.Supported {
		t.Skipf("no pasteboard here: %s", c)
	}
	withPool(func() {
		pb := pasteboard()
		if objc.Send[int](pb, selChangeCount) < 0 {
			t.Error("negative changeCount")
		}
		_ = hasAnyType(pb, concealedType)
		_ = frontmostApp()
	})
}

// Live: replaces a copied card number (skipped with -short; restores the
// pasteboard).
func TestDarwinClipboard_BlocksLive(t *testing.T) {
	if testing.Short() {
		t.Skip("touches the real pasteboard")
	}
	if !New().Supported().Supported {
		t.Skip("no pasteboard")
	}
	write := func(s string) {
		withPool(func() {
			pb := pasteboard()
			objc.Send[int](pb, selClearContents)
			objc.Send[bool](pb, selSetStringForType, nsString(s), nsString(utf8Type))
		})
	}
	read := func() (s string) {
		withPool(func() { s = goString(pasteboard().Send(selStringForType, nsString(utf8Type))) })
		return s
	}
	saved := read()
	t.Cleanup(func() { write(saved) })

	p := compile(t, blockCards)
	sink := &recSinkDarwin{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- New().Run(ctx, p, sink) }()
	time.Sleep(300 * time.Millisecond)

	write("card 4111 1111 1111 1111")
	deadline := time.Now().Add(3 * time.Second)
	for read() != "Blocked by SentinelOps: credit card" {
		if time.Now().After(deadline) {
			t.Fatalf("not replaced: %q", read())
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
}

type recSinkDarwin struct{ n int }

func (r *recSinkDarwin) Emit(_ events.Event) { r.n++ }
