package clipboard

import (
	"context"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"sentinelgo/internal/dlp/events"
)

type sink struct {
	mu  sync.Mutex
	evs []events.Event
}

func (s *sink) Emit(ev events.Event) { s.mu.Lock(); s.evs = append(s.evs, ev); s.mu.Unlock() }
func (s *sink) count() int           { s.mu.Lock(); defer s.mu.Unlock(); return len(s.evs) }

// readClip and writeClip use the real clipboard from the test (no owner window).
func readClip(t *testing.T) string {
	t.Helper()
	if !openClipboard(0) {
		t.Fatal("open clipboard")
	}
	defer func() { _, _, _ = procCloseClipboard.Call() }()
	h, _, _ := procGetClipboardData.Call(cfUnicodeText)
	if h == 0 {
		return ""
	}
	return globalText(h)
}

func writeClip(t *testing.T, s string, concealed bool) {
	t.Helper()
	if !openClipboard(0) {
		t.Fatal("open clipboard")
	}
	defer func() { _, _, _ = procCloseClipboard.Call() }()
	_, _, _ = procEmptyClipboard.Call()
	u16, _ := windows.UTF16FromString(s)
	if err := setGlobal(cfUnicodeText, u16Bytes(u16)); err != nil {
		t.Fatalf("set clipboard: %v", err)
	}
	if concealed {
		_ = setGlobal(fmtExcludeMonitor(), []byte{0, 0, 0, 0})
	}
}

// clipboardOrSkip returns the current clipboard text, or skips the test when
// another process holds the clipboard (an environment problem, not a bug).
func clipboardOrSkip(t *testing.T) string {
	t.Helper()
	if !openClipboard(0) {
		t.Skip("another process is holding the clipboard open")
	}
	_, _, _ = procCloseClipboard.Call()
	return readClip(t)
}

// Live: copy a card number, the watcher replaces it with the placeholder
// before a human could paste, and records an event. Restores the clipboard.
func TestWindowsClipboard_BlocksLive(t *testing.T) {
	if testing.Short() {
		t.Skip("touches the real clipboard")
	}
	ch := New()
	if !ch.Supported().Supported {
		t.Skipf("clipboard unsupported here: %s", ch.Supported())
	}
	saved := clipboardOrSkip(t)
	t.Cleanup(func() { writeClip(t, saved, false) })

	p := compile(t, `{"id":"p","name":"cards","severity":"high","channels":["clipboard"],"action":"block","match":"any",
		"detectors":[{"id":"pii.credit_card","rule_id":"r1","min_count":1}]}`)
	p.Modules.Clipboard.IgnoreConcealed = true
	s := &sink{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ch.Run(ctx, p, s) }()
	time.Sleep(200 * time.Millisecond) // window up

	start := time.Now()
	writeClip(t, "card 4111 1111 1111 1111", false)
	for readClip(t) != "Blocked by SentinelOps: credit card" {
		if time.Since(start) > 2*time.Second {
			t.Fatalf("not replaced; clipboard = %q", readClip(t))
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Logf("replaced %v after the copy", time.Since(start))
	if time.Since(start) > 100*time.Millisecond {
		t.Errorf("replacement took %v, want < 100 ms", time.Since(start))
	}
	if s.count() != 1 {
		t.Errorf("events = %d, want 1", s.count())
	}

	// Our own placeholder isn't rescanned; a password-manager copy is ignored.
	writeClip(t, "4111111111111111", true)
	time.Sleep(300 * time.Millisecond)
	if got := readClip(t); got != "4111111111111111" {
		t.Errorf("concealed copy replaced: %q", got)
	}
	if s.count() != 1 {
		t.Errorf("events = %d after a concealed copy, want still 1", s.count())
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run didn't return after cancel")
	}
}

// Many copies: no handle or goroutine growth, and Run can start and stop
// repeatedly (one window class, one callback).
func TestWindowsClipboard_RestartAndManyCopies(t *testing.T) {
	if testing.Short() {
		t.Skip("touches the real clipboard")
	}
	if !New().Supported().Supported {
		t.Skip("clipboard unsupported here")
	}
	saved := clipboardOrSkip(t)
	t.Cleanup(func() { writeClip(t, saved, false) })
	p := compile(t, monitorFalcon)
	for range 3 {
		s := &sink{}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- New().Run(ctx, p, s) }()
		time.Sleep(100 * time.Millisecond)
		for i := range 200 {
			writeClip(t, "plain text "+string(rune('a'+i%26)), false)
		}
		cancel()
		<-done
	}
}
