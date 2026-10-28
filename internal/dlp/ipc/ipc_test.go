//go:build windows || linux || darwin

package ipc

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/dlp/events"
)

// pair listens on a fresh address and returns both ends of one connection.
func pair(t *testing.T) (l Listener, server, client Conn, addr string) {
	t.Helper()
	addr = testAddress(t)
	l, err := Listen(addr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	accepted := make(chan Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			t.Errorf("Accept: %v", err)
			close(accepted)
			return
		}
		accepted <- c
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err = Dial(ctx, addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	server = <-accepted
	if server == nil {
		t.FailNow()
	}
	t.Cleanup(func() { _ = server.Close(); _ = client.Close() })
	return l, server, client, addr
}

func TestTransport_RoundTrip(t *testing.T) {
	_, server, client, _ := pair(t)

	go func() {
		_ = Write(client, Message{Type: TypeHello, Hello: &Hello{PID: 42, Capabilities: map[string]string{"clipboard": "supported"}}})
		_ = Write(client, Message{Type: TypeEvent, Event: &events.Event{EventID: "e1", User: `forged\admin`}})
	}()
	m, err := Read(server, MaxHelperFrame)
	if err != nil || m.Type != TypeHello || m.Hello.Capabilities["clipboard"] != "supported" {
		t.Fatalf("hello = %+v, %v", m, err)
	}
	m, err = Read(server, MaxHelperFrame)
	if err != nil || m.Type != TypeEvent || m.Event.EventID != "e1" {
		t.Fatalf("event = %+v, %v", m, err)
	}

	big := bytes.Repeat([]byte("x"), 2<<20) // a 2 MB policy fits the service limit
	go func() { _ = Write(server, Message{Type: TypePolicy, Policy: []byte(`"` + string(big) + `"`)}) }()
	m, err = Read(client, MaxServiceFrame)
	if err != nil || m.Type != TypePolicy || len(m.Policy) != len(big)+2 {
		t.Fatalf("policy frame: type=%s len=%d err=%v", m.Type, len(m.Policy), err)
	}
}

// The identity in events comes from the OS, never from message fields.
func TestTransport_PeerIdentityFromOS(t *testing.T) {
	_, server, client, _ := pair(t)
	id, err := PeerIdentity(server)
	if err != nil {
		t.Fatalf("PeerIdentity: %v", err)
	}
	if !SameUser(id) || id.User == "" || id.PID == 0 || id.SessionID == "" {
		t.Errorf("peer identity = %+v, want this process's user", id)
	}
	sid, err := ServerIdentity(client)
	if err != nil {
		t.Fatalf("ServerIdentity: %v", err)
	}
	if !TrustedServer(sid) {
		t.Errorf("server %+v not trusted although it is this user", sid)
	}
	if TrustedServer(Identity{UID: "S-1-5-21-1-2-3-1001-not-me"}) && !IsPrivileged(Identity{UID: "S-1-5-21-1-2-3-1001-not-me"}) {
		t.Error("another user's server trusted")
	}
}

func TestTransport_OversizedFrameRejected(t *testing.T) {
	_, server, client, _ := pair(t)
	go func() {
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], MaxHelperFrame+1)
		_, _ = client.Write(hdr[:])
	}()
	if _, err := Read(server, MaxHelperFrame); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("Read = %v, want ErrFrameTooLarge", err)
	}
}

func TestTransport_CloseUnblocks(t *testing.T) {
	l, server, client, _ := pair(t)

	done := make(chan error, 1)
	go func() { _, err := Read(client, MaxServiceFrame); done <- err }()
	_ = server.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Read succeeded on a closed connection")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("peer Read not unblocked by Close")
	}

	acc := make(chan error, 1)
	go func() { _, err := l.Accept(); acc <- err }()
	time.Sleep(50 * time.Millisecond)
	_ = l.Close()
	select {
	case err := <-acc:
		if err == nil {
			t.Error("Accept succeeded after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept not unblocked by Close")
	}
}

func TestTransport_SecondListenerFails(t *testing.T) {
	_, _, _, addr := pair(t)
	if l, err := Listen(addr); err == nil {
		_ = l.Close()
		if !strings.Contains(addr, "pipe") {
			t.Skip("unix: a new listener replaces a stale socket by design")
		}
		t.Error("a second listener took over the pipe name")
	}
}

func TestReadRejectsBadFrames(t *testing.T) {
	frame := func(s string) *bytes.Reader {
		var b bytes.Buffer
		_ = binary.Write(&b, binary.BigEndian, uint32(len(s)))
		b.WriteString(s)
		return bytes.NewReader(b.Bytes())
	}
	for name, body := range map[string]string{
		"not json":      "{",
		"wrong proto":   `{"proto":2,"type":"ping"}`,
		"missing type":  `{"proto":1}`,
		"truncated hdr": "",
	} {
		r := frame(body)
		if name == "truncated hdr" {
			r = bytes.NewReader([]byte{0, 0})
		}
		if _, err := Read(r, MaxHelperFrame); err == nil {
			t.Errorf("%s: Read succeeded", name)
		}
	}
}
