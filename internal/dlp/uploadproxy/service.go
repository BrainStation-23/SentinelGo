package uploadproxy

// The upload proxy as part of the service (#344 phase 2). When the bundle
// turns inspection on (modules.files.uploads.inspection, Compliance-OS#532)
// the service:
//
//  1. starts the proxy on loopback, scanning uploads in the sandboxed
//     workers (never in the service, #328);
//  2. puts the inspection CA in the system trust store (Truster);
//  3. points the system proxy at the PAC script it serves (Redirector):
//     only the destinations in scope go through the proxy, everything else
//     and every bypass host goes direct.
//
// While the redirect is active and the files module isn't audit_only, it
// also blocks direct connections to the intercepted sites from other
// processes (directblock.go, Windows: WFP), so apps that ignore the proxy
// can't go around it.
//
// It fails open: the PAC script says "PROXY …; DIRECT", so browsers go
// direct when the proxy is down; a watchdog removes the redirect when the
// proxy stops answering, when the emergency switch is on, and on stop; and
// a crashed agent's redirect is removed on the next start. Turning
// inspection off also takes the CA out of the trust store.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/filedlp"
	"sentinelgo/internal/dlp/policy"
	"sentinelgo/internal/dlp/scanworker"
	"sentinelgo/internal/winsec"
)

// Service defaults.
const (
	// DefaultAddr is where the proxy listens: loopback only. Another port is
	// taken when it is busy (the PAC URL follows).
	DefaultAddr = "127.0.0.1:3129"
	// SpillDir holds upload bodies while they are inspected (config dir).
	SpillDir = "upload-spill"
)

// Tuning; vars for tests.
var (
	watchdogEvery = 10 * time.Second
	probeTimeout  = 3 * time.Second
)

// Redirect and proxy states in the status.
const (
	unsupported      = "unsupported:" // prefix of a capability that can't work, with its reason
	RedirectActive   = "active"
	RedirectInactive = "inactive"
	ProxyHealthy     = "healthy"
	ProxyDown        = "down"
)

// ServiceOptions configure a Service.
type ServiceOptions struct {
	Sink      channel.EventSink
	Exe       string // the agent binary, run as scan workers
	ConfigDir string // the CA, spill files, redirect note, emergency switch
	Addr      string // default DefaultAddr
	// The OS integration; nil means this OS's (NewRedirector, NewTruster).
	Redirector Redirector
	Truster    Truster
	// DirectBlocker and Resolver replace this OS's direct block (tests);
	// where the OS has none (platformDirectBlocker nil) and no DirectBlocker
	// is given, there is no direct block.
	DirectBlocker func() (DirectBlocker, error)
	Resolver      Resolver
	// Scanner replaces the worker pool (tests); nil starts workers.
	Scanner filedlp.Scanner
	// ProxyTestOptions lets tests reach local upstreams (their roots,
	// loopback targets); nil in the agent.
	ProxyTestOptions *Options
}

// Status is the upload inspection's state in the DLP status report
// (files.deep_inspection, Compliance-OS#532).
type Status struct {
	CA               *CAStatus  `json:"ca,omitempty"`
	Redirect         string     `json:"redirect"` // active, inactive, unsupported:<reason>
	Proxy            string     `json:"proxy"`    // healthy, down
	Addr             string     `json:"addr,omitempty"`
	LastInspectionAt *time.Time `json:"last_inspection_at,omitempty"`
	Stats            Stats      `json:"stats"`
	// DirectBlock is the block on direct connections (Windows, #427); nil
	// where the OS has none.
	DirectBlock *DirectBlockStatus `json:"direct_block,omitempty"`
}

// CAStatus describes the inspection CA (never its key).
type CAStatus struct {
	FingerprintSHA256    string    `json:"fingerprint_sha256"`
	CreatedAt            time.Time `json:"created_at"`
	NotAfter             time.Time `json:"not_after"`
	TrustedInSystemStore bool      `json:"trusted_in_system_store"`
	// TrustError is why the agent couldn't trust it (ca_needs_mdm, …).
	TrustError string `json:"trust_error,omitempty"`
}

// Service runs the proxy for the policy. It is safe for concurrent use.
type Service struct {
	opts  ServiceOptions
	redir Redirector
	trust Truster

	mu       sync.Mutex
	running  bool
	tried    bool
	failure  string // why it couldn't start ("" when it could)
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	ln       net.Listener
	proxy    *Proxy
	pool     *scanworker.Pool
	decider  *filedlp.Decider
	ca       *CA
	trustErr string
	pacURL   string

	scope    atomic.Pointer[func(host, port string) bool]
	pac      atomic.Pointer[[]byte]
	hosts    atomic.Pointer[[2][]string] // intercept, bypass applied
	redirect atomic.Pointer[string]      // active, inactive, unsupported:<reason>
	healthy  atomic.Bool
	localOff atomic.Bool

	direct    *directBlock // nil where the OS has no direct block
	auditOnly atomic.Bool
}

// NewService returns a Service. It removes a redirect a crashed agent left.
func NewService(o ServiceOptions) *Service {
	if o.Addr == "" {
		o.Addr = DefaultAddr
	}
	s := &Service{opts: o, redir: o.Redirector, trust: o.Truster}
	if s.redir == nil {
		s.redir = NewRedirector(o.ConfigDir)
	}
	if s.trust == nil {
		s.trust = NewTruster()
	}
	if err := s.redir.Remove(); err != nil {
		log.Printf("DLP: could not remove a stale upload redirect: %v", err)
	}
	open, resolve := o.DirectBlocker, o.Resolver
	if open == nil {
		open = platformDirectBlocker
	}
	if resolve == nil {
		resolve = platformResolver
	}
	if open != nil && resolve != nil {
		s.direct = newDirectBlock(open, resolve)
	}
	s.auditOnly.Store(true)
	inactive := RedirectInactive
	s.redirect.Store(&inactive)
	none := func(string, string) bool { return false }
	s.scope.Store(&none)
	empty := []byte{}
	s.pac.Store(&empty)
	return s
}

// Wants reports whether m turns inspection on.
func (s *Service) Wants(m policy.FilesModule) bool { return m.InspectsUploads() }

// Apply switches to c: starts, rescopes or stops the proxy.
func (s *Service) Apply(_ context.Context, c *policy.Compiled) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c == nil || !c.Modules.Files.InspectsUploads() {
		if s.running {
			s.stopLocked()
		}
		if s.tried {
			s.untrustLocked() // turned off: the CA leaves the trust store
		}
		return
	}
	if !s.running {
		s.startLocked()
		if !s.running {
			return
		}
	}
	s.decider.Apply(c)
	if s.pool != nil {
		if raw, err := json.Marshal(c.Bundle); err == nil {
			s.pool.SetPolicy(raw)
		}
	}
	in := c.Modules.Files.Uploads.Inspection
	scope := Scope(in.Intercept, in.Bypass)
	s.scope.Store(&scope)
	pac := BuildPAC(s.ln.Addr().String(), in.Intercept, in.Bypass)
	s.pac.Store(&pac)
	s.hosts.Store(&[2][]string{in.Intercept, in.Bypass})
	s.auditOnly.Store(c.Modules.Files.IsAuditOnly())
}

// Stop stops the proxy and removes the redirect. The CA stays trusted: Stop
// is also the agent shutting down, and inspection comes back with it.
func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopLocked()
}

func (s *Service) startLocked() {
	s.tried = true
	s.failure = ""
	ca, err := LoadOrCreateCA(s.opts.ConfigDir)
	if err != nil {
		s.failure = "unavailable:ca_error"
		log.Printf("DLP: upload inspection CA: %v", err)
		return
	}
	spill := filepath.Join(s.opts.ConfigDir, SpillDir)
	if err := ResetSpillDir(spill); err != nil {
		s.failure = "unavailable:spill_dir"
		log.Printf("DLP: upload spill directory: %v", err)
		return
	}
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		s.failure = "unavailable:listen"
		log.Printf("DLP: upload proxy can't listen: %v", err)
		return
	}
	scanner := s.opts.Scanner
	if scanner == nil {
		s.pool = scanworker.NewPool(scanworker.Options{Exe: s.opts.Exe})
		scanner = s.pool
	}
	s.decider = filedlp.NewDecider(scanner, s.opts.Sink)
	o := Options{
		CA:        ca,
		InScope:   func(host, port string) bool { return (*s.scope.Load())(host, port) },
		Inspector: NewInspector(s.decider, spill),
		PAC:       func() []byte { return *s.pac.Load() },
	}
	if t := s.opts.ProxyTestOptions; t != nil {
		o.UpstreamRoots, o.AllowLocalTargets = t.UpstreamRoots, t.AllowLocalTargets
	}
	s.ca, s.ln, s.proxy = ca, ln, New(o)
	s.pacURL = PACURL(ln.Addr().String())
	if err := s.trust.Trust(ca); err != nil {
		s.trustErr = Reason(err)
		log.Printf("DLP: upload inspection CA not trusted: %v", err)
	} else {
		s.trustErr = ""
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel, s.running = cancel, true
	s.healthy.Store(true)
	proxy := s.proxy
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		if err := proxy.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("DLP: upload proxy stopped: %v", err)
		}
	}()
	go s.watchdog(ctx, ln.Addr().String())
	log.Printf("DLP: upload inspection started on %s", ln.Addr())
}

func (s *Service) stopLocked() {
	if !s.running {
		return
	}
	s.running = false
	s.cancel()
	_ = s.ln.Close()
	s.wg.Wait()
	if s.direct != nil {
		s.direct.stop(DirectBlockInactive)
	}
	s.removeRedirect()
	if s.pool != nil {
		s.pool.Stop()
		s.pool = nil
	}
	s.healthy.Store(false)
	log.Printf("DLP: upload inspection stopped")
}

func (s *Service) untrustLocked() {
	if err := s.trust.Untrust(); err != nil {
		log.Printf("DLP: could not remove the upload inspection CA: %v", err)
	}
}

// watchdog keeps the redirect in place while the proxy answers and the
// emergency switch is off, and removes it otherwise.
func (s *Service) watchdog(ctx context.Context, addr string) {
	defer s.wg.Done()
	t := time.NewTicker(watchdogEvery)
	defer t.Stop()
	for {
		off := s.offSwitch()
		s.localOff.Store(off)
		healthy := probe(ctx, addr)
		s.healthy.Store(healthy)
		redirecting := healthy && !off && len(*s.pac.Load()) > 0
		if redirecting {
			s.applyRedirect()
		} else {
			s.removeRedirect()
		}
		s.syncDirectBlock(ctx, redirecting)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// syncDirectBlock blocks direct connections to the intercepted sites while
// the redirect is active and the module may block, and removes the block
// otherwise (fail open with the redirect).
func (s *Service) syncDirectBlock(ctx context.Context, redirecting bool) {
	if s.direct == nil {
		return
	}
	hosts := s.hosts.Load()
	switch {
	case !redirecting || hosts == nil || *s.redirect.Load() != RedirectActive:
		s.direct.stop(DirectBlockInactive)
	case s.auditOnly.Load():
		s.direct.stop(DirectBlockAuditOnly)
	default:
		s.direct.update(ctx, hosts[0], hosts[1])
	}
}

// probe asks the proxy for its PAC script.
func probe(ctx context.Context, addr string) bool {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, PACURL(addr), nil)
	if err != nil {
		return false
	}
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func (s *Service) applyRedirect() {
	s.mu.Lock()
	url := s.pacURL
	s.mu.Unlock()
	state := RedirectActive
	if err := s.redir.Apply(url); err != nil {
		state = unsupported + Reason(err)
		if cur := s.redirect.Load(); cur == nil || *cur != state {
			log.Printf("DLP: upload redirect not applied: %v", err)
		}
	}
	s.redirect.Store(&state)
}

func (s *Service) removeRedirect() {
	cur := s.redirect.Load()
	if err := s.redir.Remove(); err != nil {
		log.Printf("DLP: could not remove the upload redirect: %v", err)
		return
	}
	if cur != nil && strings.HasPrefix(*cur, unsupported) && s.running {
		return // keep the reason while running
	}
	inactive := RedirectInactive
	s.redirect.Store(&inactive)
}

func (s *Service) offSwitch() bool {
	if s.opts.ConfigDir == "" {
		return false
	}
	_, err := os.Lstat(filepath.Join(s.opts.ConfigDir, filedlp.OffSwitchFile))
	return err == nil
}

// Capability is file.upload's capability: supported only when uploads are
// really inspected (proxy up, redirect in place, CA trusted).
func (s *Service) Capability() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.failure != "":
		return unsupported + strings.TrimPrefix(s.failure, "unavailable:")
	case !s.running:
		return "unsupported:not_running"
	case s.localOff.Load():
		return "unsupported:disabled_locally"
	case !s.healthy.Load():
		return "unsupported:proxy_down"
	case s.trustErr != "":
		return unsupported + s.trustErr
	}
	if r := *s.redirect.Load(); r != RedirectActive {
		if strings.HasPrefix(r, unsupported) {
			return r
		}
		return "unsupported:redirect_inactive"
	}
	return "supported"
}

// Status is the deep_inspection report; nil when inspection never started.
func (s *Service) Status() *Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.tried {
		return nil
	}
	st := &Status{Redirect: *s.redirect.Load(), Proxy: ProxyDown}
	if s.running && s.healthy.Load() {
		st.Proxy = ProxyHealthy
	}
	if s.ca != nil {
		cert := s.ca.Certificate()
		sum := sha256.Sum256(cert.Raw)
		st.CA = &CAStatus{FingerprintSHA256: hex.EncodeToString(sum[:]), CreatedAt: cert.NotBefore.UTC(), NotAfter: cert.NotAfter.UTC(),
			TrustedInSystemStore: systemTrusts(s.ca), TrustError: s.trustErr}
	}
	if s.proxy != nil {
		st.Stats = s.proxy.Stats()
		if t := s.proxy.LastInspection(); !t.IsZero() {
			u := t.UTC()
			st.LastInspectionAt = &u
		}
	}
	if s.running && s.ln != nil {
		st.Addr = s.ln.Addr().String()
	}
	if s.direct != nil {
		d := s.direct.status()
		st.DirectBlock = &d
	}
	return st
}

// ResetSpillDir creates dir (owner only; on Windows SYSTEM, Administrators
// and this account) and empties it of spill files a crash may have left.
func ResetSpillDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := winsec.SecurePath(dir); err != nil {
		return fmt.Errorf("secure %s: %w", filepath.Base(dir), err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
	return nil
}
