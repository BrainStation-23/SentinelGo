package uploadproxy

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/dlp/filedlp"
	"sentinelgo/internal/dlp/filescan"
	"sentinelgo/internal/dlp/policy"
)

// fakeDNS answers from a map and counts lookups.
type fakeDNS struct {
	mu      sync.Mutex
	answers map[string][]string
	ttl     time.Duration
	fail    map[string]bool
	lookups map[string]int
}

func newFakeDNS() *fakeDNS {
	return &fakeDNS{answers: map[string][]string{}, ttl: time.Minute, fail: map[string]bool{}, lookups: map[string]int{}}
}

func (f *fakeDNS) set(host string, addrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[host] = addrs
}

func (f *fakeDNS) resolve(_ context.Context, host string) ([]netip.Addr, time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups[host]++
	if f.fail[host] {
		return nil, 0, errors.New("servfail")
	}
	var out []netip.Addr
	for _, a := range f.answers[host] {
		out = append(out, netip.MustParseAddr(a))
	}
	return out, f.ttl, nil
}

// fakeBlocker records the blocked set.
type fakeBlocker struct {
	mu     sync.Mutex
	addrs  []netip.Addr
	tcp    bool
	sets   int
	open   bool
	opens  int
	setErr error
}

func (f *fakeBlocker) Set(a []netip.Addr, tcp bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.setErr != nil {
		return f.setErr
	}
	f.addrs, f.tcp, f.sets = slices.Clone(a), tcp, f.sets+1
	return nil
}

// openCount is how often the blocker was opened.
func (f *fakeBlocker) openCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.opens
}

// blocksTCP reports whether the last Set blocked TCP too.
func (f *fakeBlocker) blocksTCP() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tcp
}

func (f *fakeBlocker) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.open, f.addrs = false, nil
	return nil
}

func (f *fakeBlocker) opener() func() (DirectBlocker, error) {
	return func() (DirectBlocker, error) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.open, f.opens = true, f.opens+1
		return f, nil
	}
}

func (f *fakeBlocker) blocked() (bool, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := make([]string, 0, len(f.addrs))
	for _, a := range f.addrs {
		s = append(s, a.String())
	}
	return f.open, strings.Join(s, ",")
}

func TestDirectBlockUpdate(t *testing.T) {
	dns := newFakeDNS()
	dns.set("drive.example.com", "192.0.2.10", "192.0.2.20", "2001:db8::a")
	dns.set("login.example.com", "192.0.2.20") // shared with a bypass host
	fb := &fakeBlocker{}
	d := newDirectBlock(fb.opener(), dns.resolve)

	d.update(context.Background(), []string{"drive.example.com", "*.dropbox.com", "missing.example.com"}, []string{"login.example.com"}, policy.DirectBlockQUIC)
	open, got := fb.blocked()
	if !open || got != "192.0.2.10,2001:db8::a" || fb.blocksTCP() {
		t.Fatalf("blocked %v %q tcp %v", open, got, fb.blocksTCP())
	}
	st := d.status()
	if st.State != DirectBlockActive || st.Mode != "quic" || !slices.Equal(st.Protocols, []string{"udp"}) ||
		st.Addresses != 2 || st.Patterns != 1 || st.Unresolved != 1 {
		t.Errorf("status %+v", st)
	}
	d.update(context.Background(), []string{"drive.example.com"}, []string{"login.example.com"}, policy.DirectBlockQUIC)
	if fb.sets != 1 {
		t.Errorf("unchanged set rewritten: %d", fb.sets)
	}

	// Strict adds TCP to the same addresses, and going back drops it.
	d.update(context.Background(), []string{"drive.example.com"}, []string{"login.example.com"}, policy.DirectBlockStrict)
	if !fb.blocksTCP() || fb.sets != 2 {
		t.Errorf("strict: tcp %v, sets %d", fb.blocksTCP(), fb.sets)
	}
	if st := d.status(); st.Mode != "strict" || !slices.Equal(st.Protocols, []string{"tcp", "udp"}) || st.TCP != TCPRefuse {
		t.Errorf("strict status %+v", st)
	}
	d.update(context.Background(), []string{"drive.example.com"}, []string{"login.example.com"}, policy.DirectBlockQUIC)
	if fb.blocksTCP() || fb.sets != 3 || d.status().TCP != "" {
		t.Errorf("back to quic: tcp %v, sets %d, status %+v", fb.blocksTCP(), fb.sets, d.status())
	}

	// Off closes the blocker.
	d.update(context.Background(), []string{"drive.example.com"}, nil, policy.DirectBlockOff)
	if open, _ := fb.blocked(); open || d.status().State != DirectBlockOff || d.status().Mode != "off" {
		t.Errorf("off: open %v, %+v", open, d.status())
	}

	d.update(context.Background(), []string{"drive.example.com"}, nil, policy.DirectBlockQUIC)
	d.stop(DirectBlockAuditOnly, policy.DirectBlockQUIC)
	if open, _ := fb.blocked(); open || d.status().State != DirectBlockAuditOnly || d.status().Protocols != nil {
		t.Errorf("stop: open %v, %+v", open, d.status())
	}

	// A failing Set closes the blocker and says so.
	fb.setErr = errors.New("boom")
	d.update(context.Background(), []string{"drive.example.com"}, nil, policy.DirectBlockQUIC)
	if open, _ := fb.blocked(); open || d.status().State != "unsupported:error" {
		t.Errorf("set error: open %v, %+v", open, d.status())
	}

	// An open error is reported with its reason.
	d2 := newDirectBlock(func() (DirectBlocker, error) { return nil, ErrNotImplemented }, dns.resolve)
	d2.update(context.Background(), []string{"drive.example.com"}, nil, policy.DirectBlockQUIC)
	if d2.status().State != "unsupported:not_implemented" {
		t.Errorf("open error: %+v", d2.status())
	}
}

// withDirectBlock sets the inspection's direct_block in a bundle from
// inspectionBundle.
func withDirectBlock(bundle, mode string) string {
	return strings.Replace(bundle, `"inspection": {"enabled": true,`, `"inspection": {"enabled": true, "direct_block": "`+mode+`",`, 1)
}

// The service blocks direct connections only while the redirect is active
// and the module isn't audit_only, and removes the block with the redirect.
func TestService_DirectBlock(t *testing.T) {
	prev := watchdogEvery
	watchdogEvery = 50 * time.Millisecond
	t.Cleanup(func() { watchdogEvery = prev })
	dns := newFakeDNS()
	dns.set("drive.example.com", "192.0.2.10")
	fb := &fakeBlocker{}
	r := &fakeRedirector{}
	dir := t.TempDir()
	c := compileBundle(t, inspectionBundle(`"drive.example.com"`))
	eng, _ := c.FilesEngine()
	s := NewService(ServiceOptions{Sink: &recordingSink{}, ConfigDir: dir, Addr: "127.0.0.1:0", Redirector: r, Truster: &fakeTruster{},
		Scanner:       inProcess{filescan.New(eng, filescan.LimitsFrom(c.Bundle.Modules.Files), t.TempDir())},
		DirectBlocker: fb.opener(), Resolver: dns.resolve})
	t.Cleanup(s.Stop)

	// audit_only (the default): redirect, but no block.
	s.Apply(context.Background(), c)
	eventually(t, "audit-only state", func() bool {
		st := s.Status()
		return st != nil && st.DirectBlock != nil && st.DirectBlock.State == DirectBlockAuditOnly
	})
	if open, _ := fb.blocked(); open {
		t.Fatal("blocked in audit_only")
	}

	enforcing := strings.Replace(inspectionBundle(`"drive.example.com"`), `"files": {"enabled": true,`, `"files": {"enabled": true, "audit_only": false,`, 1)
	s.Apply(context.Background(), compileBundle(t, enforcing))
	eventually(t, "the block", func() bool { _, got := fb.blocked(); return got == "192.0.2.10" })
	// No direct_block in the bundle: quic, UDP only.
	if st := s.Status().DirectBlock; st.State != DirectBlockActive || st.Mode != "quic" || fb.blocksTCP() || st.Addresses != 1 {
		t.Errorf("status %+v, tcp %v", st, fb.blocksTCP())
	}

	// strict adds TCP; off removes the block (and never reopens it).
	s.Apply(context.Background(), compileBundle(t, withDirectBlock(enforcing, "strict")))
	eventually(t, "strict", func() bool { return fb.blocksTCP() })
	s.Apply(context.Background(), compileBundle(t, withDirectBlock(enforcing, "off")))
	eventually(t, "off", func() bool { st := s.Status().DirectBlock; return st != nil && st.State == DirectBlockOff })
	opens := fb.openCount()
	if open, _ := fb.blocked(); open {
		t.Error("blocked with direct_block off")
	}
	time.Sleep(3 * watchdogEvery)
	if fb.openCount() != opens {
		t.Error("off reopened the blocker")
	}
	// An unknown value is quic.
	s.Apply(context.Background(), compileBundle(t, withDirectBlock(enforcing, "bogus")))
	eventually(t, "quic again", func() bool {
		st := s.Status().DirectBlock
		return st != nil && st.State == DirectBlockActive && st.Mode == "quic" && !fb.blocksTCP()
	})

	// The emergency switch removes it with the redirect.
	off := filepath.Join(dir, filedlp.OffSwitchFile)
	if err := os.WriteFile(off, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the block to go", func() bool { open, _ := fb.blocked(); return !open })
	if err := os.Remove(off); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the block back", func() bool { open, _ := fb.blocked(); return open })

	s.Stop()
	if open, _ := fb.blocked(); open {
		t.Error("block outlived Stop")
	}
	if st := s.Status().DirectBlock; st.State != DirectBlockInactive {
		t.Errorf("after stop %+v", st)
	}
}

// redirectingBlocker is a blocker that redirects TCP (the Linux backstop).
type redirectingBlocker struct{ fakeBlocker }

func (*redirectingBlocker) TCPAction() string { return TCPRedirect }

// The status says what strict does to TCP: whatever the blocker reports.
func TestDirectBlockUpdate_TCPAction(t *testing.T) {
	dns := newFakeDNS()
	dns.set("drive.example.com", "192.0.2.10")
	rb := &redirectingBlocker{}
	d := newDirectBlock(func() (DirectBlocker, error) { return rb, nil }, dns.resolve)
	d.update(context.Background(), []string{"drive.example.com"}, nil, policy.DirectBlockStrict)
	if st := d.status(); st.State != DirectBlockActive || st.TCP != TCPRedirect {
		t.Errorf("status %+v", st)
	}
}

// Without the nft command the direct block is unsupported with that reason.
func TestDirectBlockUpdate_NoNft(t *testing.T) {
	dns := newFakeDNS()
	dns.set("drive.example.com", "192.0.2.10")
	d := newDirectBlock(func() (DirectBlocker, error) { return nil, fmt.Errorf("%w: nft not found", ErrNoNft) }, dns.resolve)
	d.update(context.Background(), []string{"drive.example.com"}, nil, policy.DirectBlockQUIC)
	if st := d.status(); st.State != "unsupported:no_nft" {
		t.Errorf("status %+v", st)
	}
}
