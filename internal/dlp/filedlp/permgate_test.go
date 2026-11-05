package filedlp

import (
	"context"
	"sync"
	"testing"
	"time"
)

type replies struct {
	mu  sync.Mutex
	got map[int][]bool
	ch  chan int
}

func newReplies() *replies { return &replies{got: map[int][]bool{}, ch: make(chan int, 1024)} }

func (r *replies) reply(id int, allow bool) {
	r.mu.Lock()
	r.got[id] = append(r.got[id], allow)
	r.mu.Unlock()
	r.ch <- id
}

func (r *replies) wait(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-r.ch:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d answers", i, n)
		}
	}
}

func (r *replies) answer(t *testing.T, id int) bool {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.got[id]) != 1 {
		t.Fatalf("id %d answered %d times: %v", id, len(r.got[id]), r.got[id])
	}
	return r.got[id][0]
}

func TestPermGate_DecisionAndTimer(t *testing.T) {
	r := newReplies()
	g := newPermGate(16, r.reply)
	g.submit(1, time.Second, false, func(context.Context) bool { return true })
	g.submit(2, time.Second, false, func(context.Context) bool { return false })
	g.allowNow(3)
	// too slow: the timer answers allow, the late block is dropped
	g.submit(4, 30*time.Millisecond, false, func(ctx context.Context) bool { <-ctx.Done(); return true })
	// too slow with on_timeout: block
	g.submit(5, 30*time.Millisecond, true, func(ctx context.Context) bool { <-ctx.Done(); return false })
	r.wait(t, 5)
	time.Sleep(50 * time.Millisecond) // late decisions must not answer again
	if r.answer(t, 1) || !r.answer(t, 2) || !r.answer(t, 3) || !r.answer(t, 4) || r.answer(t, 5) {
		t.Fatal("wrong answers")
	}
	st := g.stats()
	if st.Denied != 2 || st.Allowed != 3 || st.Timeouts != 2 || st.TimeoutDenied != 1 || st.Pending != 0 {
		t.Fatalf("%+v", st)
	}
}

// Flooding the agent can't make the desktop wait: past maxPending, opens
// are allowed at once and counted.
func TestPermGate_OverloadFailsOpen(t *testing.T) {
	r := newReplies()
	g := newPermGate(2, r.reply)
	release := make(chan struct{})
	slow := func(context.Context) bool { <-release; return true }
	g.submit(1, time.Minute, false, slow)
	g.submit(2, time.Minute, false, slow)
	g.submit(3, time.Minute, false, slow)
	r.wait(t, 1)
	if !r.answer(t, 3) || g.stats().Overloaded != 1 {
		t.Fatalf("%+v", g.stats())
	}
	close(release)
	r.wait(t, 2)
}

func TestPermGate_PanicFailsOpen(t *testing.T) {
	r := newReplies()
	g := newPermGate(4, r.reply)
	g.submit(1, time.Second, false, func(context.Context) bool { panic("parser bug") })
	r.wait(t, 1)
	if !r.answer(t, 1) {
		t.Fatal("a panicking decision blocked")
	}
}

// Stop answers everything held with allow at once, even a decision that
// never returns, and allows what comes after.
func TestPermGate_StopReleasesAll(t *testing.T) {
	old := permStopWait
	permStopWait = 50 * time.Millisecond
	t.Cleanup(func() { permStopWait = old })
	r := newReplies()
	g := newPermGate(8, r.reply)
	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })
	g.submit(1, time.Hour, true, func(context.Context) bool { <-stuck; return true }) // ignores ctx
	g.submit(2, time.Hour, true, func(ctx context.Context) bool { <-ctx.Done(); return true })
	start := time.Now()
	g.stop()
	if time.Since(start) > time.Second {
		t.Fatal("stop waited for a stuck decision")
	}
	g.submit(3, time.Hour, true, func(context.Context) bool { return true })
	r.wait(t, 3)
	if !r.answer(t, 1) || !r.answer(t, 2) || !r.answer(t, 3) {
		t.Fatal("not allowed on stop")
	}
}

// Many concurrent opens each get exactly one answer.
func TestPermGate_ExactlyOnce(t *testing.T) {
	r := newReplies()
	g := newPermGate(1000, r.reply)
	for i := 0; i < 500; i++ {
		d := time.Duration(i%7) * time.Millisecond
		g.submit(i, 3*time.Millisecond, i%2 == 0, func(ctx context.Context) bool {
			select {
			case <-time.After(d):
			case <-ctx.Done():
			}
			return i%3 == 0
		})
	}
	r.wait(t, 500)
	time.Sleep(30 * time.Millisecond)
	for i := 0; i < 500; i++ {
		r.answer(t, i)
	}
	if g.stats().Pending != 0 {
		t.Fatal("pending left")
	}
}
