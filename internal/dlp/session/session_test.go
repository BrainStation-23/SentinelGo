//go:build windows || linux || darwin

package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/ipc"
	"sentinelgo/internal/dlp/policy"
)

// fakeChannel records each Run's policy version and emits one event per run,
// claiming to be someone else.
type fakeChannel struct {
	mu   sync.Mutex
	runs []string
}

func (c *fakeChannel) Name() string                  { return policy.ChannelClipboard }
func (c *fakeChannel) Supported() channel.Capability { return channel.Supported() }
func (c *fakeChannel) Run(ctx context.Context, p *policy.Compiled, sink channel.EventSink) error {
	c.mu.Lock()
	c.runs = append(c.runs, p.Version)
	c.mu.Unlock()
	sink.Emit(events.Event{EventID: events.NewID(), PolicyVersion: p.Version, User: `EVIL\forged`, SessionID: "999"})
	<-ctx.Done()
	return ctx.Err()
}

func (c *fakeChannel) versions() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.runs...)
}

func compiled(t *testing.T, version string, enabled bool) *policy.Compiled {
	t.Helper()
	b, err := policy.Decode(fmt.Appendf(nil, `{"schema_version":1,"version":%q,"enabled":%v,"modules":{"clipboard":{"enabled":true}}}`, version, enabled))
	if err != nil {
		t.Fatal(err)
	}
	return policy.Compile(b)
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// End to end over the real transport: the helper gets the policy, its
// channel runs, events reach the sink with the OS identity, a new policy
// restarts the channel, and Stop makes the helper exit.
func TestHubAndHelper(t *testing.T) {
	addr := testAddress(t)
	sink := &recordingSink{}
	hub := NewHub(addr, sink)
	hub.Apply(context.Background(), compiled(t, "v1", true))
	t.Cleanup(hub.Stop)

	ch := &fakeChannel{}
	done := make(chan error, 1)
	go func() {
		done <- RunHelper(context.Background(), HelperOptions{
			Addr: addr, Version: "test", Channels: []channel.Channel{ch},
			Backoff: func(int) time.Duration { return 20 * time.Millisecond },
		})
	}()

	eventually(t, "the first event", func() bool { return len(sink.events()) == 1 })
	ev := sink.events()[0]
	if ev.User == `EVIL\forged` || ev.SessionID == "999" || ev.User == "" {
		t.Errorf("event identity %q/%q came from the helper, not the OS", ev.User, ev.SessionID)
	}
	if ev.PolicyVersion != "v1" {
		t.Errorf("policy version = %q", ev.PolicyVersion)
	}
	eventually(t, "the helper's status", func() bool {
		s := hub.Sessions()
		return len(s) == 1 && s[0].State == "running" && s[0].User == ev.User
	})

	hub.Apply(context.Background(), compiled(t, "v2", true))
	eventually(t, "the channel to restart on v2", func() bool {
		v := ch.versions()
		return len(v) == 2 && v[1] == "v2"
	})

	hub.Stop()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("RunHelper = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("helper didn't exit after Stop")
	}
	if len(hub.Sessions()) != 0 {
		t.Errorf("sessions after Stop = %+v", hub.Sessions())
	}
}

// When the service goes away (crash, restart) the helper keeps enforcing the
// last policy and buffers events; a new service instance on the same
// address gets them once the helper reconnects.
func TestHelperSurvivesServiceRestart(t *testing.T) {
	addr := testAddress(t)
	prev := listenRetry
	listenRetry = func(int) time.Duration { return 20 * time.Millisecond }
	t.Cleanup(func() { listenRetry = prev })

	sink := &recordingSink{}
	hub := NewHub(addr, sink)
	hub.Apply(context.Background(), compiled(t, "v1", true))

	ch := &fakeChannel{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt := &helperRuntime{o: HelperOptions{Addr: addr, Channels: []channel.Channel{ch}}}
	rtDone := make(chan struct{})
	go func() {
		defer close(rtDone)
		for ctx.Err() == nil {
			if stop, _ := rt.connectOnce(ctx); stop {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	eventually(t, "the first event", func() bool { return len(sink.events()) == 1 })

	crash(hub) // gone without telling the helper to stop
	eventually(t, "the helper to notice", func() bool { rt.mu.Lock(); defer rt.mu.Unlock(); return rt.conn == nil })
	rt.Emit(events.Event{EventID: "buffered", PolicyVersion: "v1"})

	restarted := NewHub(addr, sink)
	restarted.Apply(context.Background(), compiled(t, "v1", true)) // same policy
	eventually(t, "the buffered event", func() bool {
		for _, ev := range sink.events() {
			if ev.EventID == "buffered" {
				return true
			}
		}
		return false
	})
	if v := ch.versions(); len(v) != 1 {
		t.Errorf("the channel restarted (versions %v); it must keep enforcing across the outage", v)
	}
	cancel()
	restarted.Stop()
	<-rtDone
	rt.stopChannels()
}

// crash drops every connection and the endpoint without a stop message.
func crash(h *Hub) {
	h.mu.Lock()
	h.running = false
	close(h.stopCh)
	l := h.l
	h.l = nil
	conns := h.snapshotLocked()
	h.mu.Unlock()
	if l != nil {
		_ = l.Close()
	}
	for _, hp := range conns {
		_ = hp.conn.Close()
	}
	h.wg.Wait()
}

// A bundle with enabled:false makes the helper exit.
func TestHelperExitsWhenDisabled(t *testing.T) {
	addr := testAddress(t)
	hub := NewHub(addr, &recordingSink{})
	hub.Apply(context.Background(), compiled(t, "off", false))
	t.Cleanup(hub.Stop)

	done := make(chan error, 1)
	go func() {
		done <- RunHelper(context.Background(), HelperOptions{Addr: addr, Channels: []channel.Channel{&fakeChannel{}}})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("RunHelper = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("helper didn't exit on enabled:false")
	}
}

// A connection that never says hello is dropped and never listed.
func TestHubDropsSilentConnections(t *testing.T) {
	addr := testAddress(t)
	hub := NewHub(addr, &recordingSink{})
	hub.Apply(context.Background(), compiled(t, "v1", true))
	t.Cleanup(hub.Stop)

	var c ipc.Conn
	eventually(t, "the endpoint", func() bool {
		var err error
		c, err = ipc.Dial(context.Background(), addr)
		return err == nil
	})
	defer func() { _ = c.Close() }()
	if err := ipc.Write(c, ipc.Message{Type: ipc.TypeEvent, Event: &events.Event{EventID: "x"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := ipc.Read(c, ipc.MaxServiceFrame); err == nil {
		t.Error("connection without hello not closed")
	}
	if len(hub.Sessions()) != 0 {
		t.Error("connection without hello listed as a session")
	}
}

// A helper that connects but never reads can't stall Apply or Stop.
func TestHubDoesNotBlockOnStuckHelper(t *testing.T) {
	addr := testAddress(t)
	prev := stopGrace
	stopGrace = 200 * time.Millisecond
	t.Cleanup(func() { stopGrace = prev })
	hub := NewHub(addr, &recordingSink{})
	big := compiled(t, "v1", true)
	big.Bundle.Policies = make([]policy.Policy, 20000) // ~ MBs of JSON, far over the pipe buffer
	hub.Apply(context.Background(), big)

	var c ipc.Conn
	eventually(t, "the endpoint", func() bool {
		var err error
		c, err = ipc.Dial(context.Background(), addr)
		return err == nil
	})
	defer func() { _ = c.Close() }()
	if err := ipc.Write(c, ipc.Message{Type: ipc.TypeHello, Hello: &ipc.Hello{}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the helper to register", func() bool { return len(hub.Sessions()) == 1 })

	done := make(chan struct{})
	go func() {
		for i := range 10 { // never read by the helper
			hub.Apply(context.Background(), compiled(t, fmt.Sprintf("v%d", i+2), true))
		}
		hub.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Apply/Stop blocked on a helper that doesn't read")
	}
}

// Only the agent's own binary may connect, a user gets a few connections at
// most, and nothing registers once the hub is stopping.
func TestHubAdmit(t *testing.T) {
	hub := NewHub("unused", &recordingSink{})
	hub.running = true
	self := ipc.Identity{UID: "u1", Exe: mustExe(t)}
	if err := hub.admit(&nopConn{}, ipc.Identity{UID: "u1", Exe: "/usr/bin/evil"}); err == nil {
		t.Error("a foreign executable was admitted")
	}
	for i := range maxConnsPerUser {
		if err := hub.admit(&nopConn{}, self); err != nil {
			t.Fatalf("connection %d rejected: %v", i, err)
		}
	}
	if err := hub.admit(&nopConn{}, self); err == nil {
		t.Error("connection over the per-user cap admitted")
	}
	if err := hub.admit(&nopConn{}, ipc.Identity{UID: "u2", Exe: self.Exe}); err != nil {
		t.Errorf("another user rejected: %v", err)
	}
	hub.running = false
	if err := hub.admit(&nopConn{}, ipc.Identity{UID: "u3", Exe: self.Exe}); err == nil {
		t.Error("admitted while stopping")
	}
}

// Stop doesn't wait on a connection that never says hello.
func TestHubStopWithSilentConnection(t *testing.T) {
	addr := testAddress(t)
	prev := stopGrace
	stopGrace = 100 * time.Millisecond
	t.Cleanup(func() { stopGrace = prev })
	hub := NewHub(addr, &recordingSink{})
	hub.Apply(context.Background(), compiled(t, "v1", true))
	var c ipc.Conn
	eventually(t, "the endpoint", func() bool {
		var err error
		c, err = ipc.Dial(context.Background(), addr)
		return err == nil
	})
	defer func() { _ = c.Close() }()
	eventually(t, "the connection to be tracked", func() bool {
		hub.mu.Lock()
		defer hub.mu.Unlock()
		return len(hub.conns) == 1
	})
	start := time.Now()
	hub.Stop()
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("Stop took %v with a silent connection open", d)
	}
}

func mustExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

type nopConn struct{ _ byte } // non-zero size: distinct pointers

func (*nopConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (*nopConn) Write(p []byte) (int, error) { return len(p), nil }
func (*nopConn) Close() error                { return nil }

// A helper that keeps refusing the endpoint exits (so the launcher restarts
// it), and the hub records why it never connected (#292).
func TestHelperExitsAfterUntrustedEndpoints(t *testing.T) {
	prev := trustServer
	trustServer = func(ipc.Identity) bool { return false }
	t.Cleanup(func() { trustServer = prev })

	addr := testAddress(t)
	hub := NewHub(addr, &recordingSink{})
	hub.Apply(context.Background(), compiled(t, "v1", true))
	t.Cleanup(hub.Stop)

	done := make(chan error, 1)
	go func() {
		done <- RunHelper(context.Background(), HelperOptions{
			Addr: addr, Channels: []channel.Channel{&fakeChannel{}},
			Backoff: func(int) time.Duration { return 10 * time.Millisecond },
		})
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errUntrusted) {
			t.Fatalf("RunHelper = %v, want errUntrusted", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("helper kept retrying an untrusted endpoint")
	}
	eventually(t, "the hub to record the failure", func() bool {
		hub.mu.Lock()
		defer hub.mu.Unlock()
		for _, reason := range hub.lastErr {
			if strings.Contains(reason, "before hello") {
				return true
			}
		}
		return false
	})
}
