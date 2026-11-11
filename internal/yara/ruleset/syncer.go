// Package ruleset keeps the device's YARA ruleset bundle current (#411): the
// yara-ruleset-sync scheduler task polls agent_get_yara_ruleset, downloads
// and verifies the rule sources, has a sandboxed scan worker compile them,
// and only then swaps them in. The last good set stays in force through any
// failure and survives an offline reboot (Cache).
//
// Rule sources are never logged: log lines name rulesets by id only.
package ruleset

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"sentinelgo/internal/yara"
)

// Poll timing. The backend answers {"changed": false} without storing the
// status to a device that calls more than once in 30 s, so polls are kept
// further apart than that, even when pushed.
const (
	PollInterval = 15 * time.Minute
	pollJitter   = 90 * time.Second
	minPollGap   = 35 * time.Second
	firstBackoff = time.Minute
)

// Fetcher calls agent_get_yara_ruleset (Client in production).
type Fetcher interface {
	FetchRuleset(ctx context.Context, knownVersion string, status *yara.Status) (FetchResult, error)
}

// Downloader downloads a rule source (Client in production).
type Downloader interface {
	DownloadRuleset(ctx context.Context, storagePath string, w io.Writer, limit int64) error
}

// Rules is a compiled rule set, opaque to this package (in production a
// *scanworker.YARARules, which the scans hand back to the worker pool).
type Rules any

// Compiler compiles rule sources in a sandboxed worker. err means no worker
// could compile at all; a ruleset that failed has CompileResult.Error.
type Compiler interface {
	Compile(ctx context.Context, sources []yara.RuleSource) (Rules, []yara.CompileResult, error)
}

// Retrier runs one server call, recovering an expired session once
// (auth.Service.DoWithAuthRetry in production).
type Retrier func(ctx context.Context, fn func() error) error

// Active is the bundle in force. It is immutable: a new bundle replaces the
// whole value, so a scan that took it keeps a consistent view.
type Active struct {
	Bundle *yara.Bundle
	// Rules is nil for a disabled bundle.
	Rules    Rules
	Compiled []yara.CompileResult
}

// Enabled reports whether a scan may run with a.
func (a *Active) Enabled() bool {
	return a != nil && a.Bundle != nil && a.Bundle.Enabled && a.Rules != nil
}

// Revision returns the revision of ruleset id in a (0 if it isn't there).
func (a *Active) Revision(id string) int {
	if a == nil || a.Bundle == nil {
		return 0
	}
	for _, r := range a.Bundle.Rulesets {
		if strings.EqualFold(r.ID, id) {
			return r.Revision
		}
	}
	return 0
}

// Options configure a Syncer.
type Options struct {
	Fetcher       Fetcher
	Downloader    Downloader
	Compiler      Compiler
	Cache         *Cache
	Retry         Retrier // nil: call directly
	AgentVersion  string
	EngineVersion string
	// WorkerHealthy reports false when the scan workers are disabled after a
	// crash loop; the status then says worker_unavailable.
	WorkerHealthy func() bool
	// OnChange is called after a new bundle is in force (enabled or not),
	// outside the Syncer's locks. A disabled bundle must stop a running
	// scan.
	OnChange func(*Active)
	// LocallyDisabled is config.json's yara_enabled false (#416): the
	// Syncer still polls, so the server sees state disabled, but never
	// applies a bundle, compiles rules or starts a worker, and deletes the
	// ruleset cache.
	LocallyDisabled bool
}

// Syncer polls for the ruleset bundle and applies it.
type Syncer struct {
	o      Options
	now    func() time.Time
	active atomic.Pointer[Active]

	syncMu   sync.Mutex // one poll at a time
	restored bool

	mu         sync.Mutex
	next       time.Time
	lastPoll   time.Time
	failures   int
	failState  string               // set while the newest bundle isn't applied
	results    []yara.CompileResult // of the last compile attempt
	lastScan   *yara.ScanSummary
	sentStatus [32]byte
	statusSent bool
	tccDenied  bool
	// seen is the newest bundle version the server sent while the agent is
	// locally disabled, so it isn't sent again on every poll.
	seen string
}

// New returns a Syncer. The first Sync loads the cache before polling.
func New(o Options) *Syncer {
	if o.Retry == nil {
		o.Retry = func(ctx context.Context, fn func() error) error { return fn() }
	}
	return &Syncer{o: o, now: time.Now}
}

// Active returns the bundle in force, or nil.
func (s *Syncer) Active() *Active { return s.active.Load() }

// Due reports whether a poll is due.
func (s *Syncer) Due() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.now().Before(s.next)
}

// PollNow makes the next tick poll (after a yara-scan task, say), but not
// within minPollGap of the last poll.
func (s *Syncer) PollNow() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next = s.lastPoll.Add(minPollGap)
}

// SetLastScan records the last scan for the status, and has it sent on the
// next poll.
func (s *Syncer) SetLastScan(sum *yara.ScanSummary) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sum != nil {
		c := *sum
		sum = &c
	}
	s.lastScan = sum
}

// Sync polls once and applies a new bundle. Errors leave the last good
// bundle in force; the next poll is then sooner (backoff from 1 min), never
// later than the normal interval.
func (s *Syncer) Sync(ctx context.Context) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	s.restoreOnce(ctx)
	err := s.poll(ctx)
	s.schedule(err)
	return err
}

func (s *Syncer) poll(ctx context.Context) error {
	known := ""
	if a := s.Active(); a != nil && a.Bundle != nil {
		known = a.Bundle.Version
	}
	if s.o.LocallyDisabled {
		known = s.seen
	}
	status := s.Status()
	data, _ := json.Marshal(status)
	hash := sha256.Sum256(data)
	send := &status
	s.mu.Lock()
	if s.statusSent && s.sentStatus == hash {
		send = nil
	}
	s.lastPoll = s.now()
	s.mu.Unlock()

	var res FetchResult
	err := s.o.Retry(ctx, func() error {
		var err error
		res, err = s.o.Fetcher.FetchRuleset(ctx, known, send)
		if errors.Is(err, ErrStatusRejected) {
			log.Printf("YARA: server rejected the status report; polling without it: %v", err)
			send = nil
			res, err = s.o.Fetcher.FetchRuleset(ctx, known, nil)
		}
		return err
	})
	if err != nil {
		return fmt.Errorf("YARA ruleset poll: %w", err)
	}
	if send != nil {
		s.mu.Lock()
		s.sentStatus, s.statusSent = hash, true
		s.mu.Unlock()
	}
	if !res.Changed {
		return nil
	}
	if s.o.LocallyDisabled {
		// Remember the version only: nothing is applied on this device.
		if b, err := yara.Decode(res.Raw); err == nil {
			s.seen = b.Version
		}
		return nil
	}
	return s.apply(ctx, res.Raw)
}

// apply decodes, downloads, compiles, caches and swaps in a new bundle.
func (s *Syncer) apply(ctx context.Context, raw []byte) error {
	b, err := yara.Decode(raw)
	if err != nil {
		state := yara.StateCompileFailed
		switch {
		case errors.Is(err, yara.ErrTooLarge):
			state = yara.StateTooLarge
		case errors.Is(err, yara.ErrUnsupportedSchema):
			state = yara.StateUnsupportedSchema
		}
		return s.fail(state, nil, fmt.Errorf("YARA: bundle not applied: %w", err))
	}
	if !b.Enabled {
		if err := s.o.Cache.Clear(); err != nil {
			log.Printf("YARA: could not delete the ruleset cache: %v", err)
		}
		log.Printf("YARA: bundle %s disables threat hunting", short(b.Version))
		s.swap(&Active{Bundle: b}, nil)
		return nil
	}
	sources, err := s.download(ctx, b)
	if err != nil {
		// Includes an object of another size than the bundle says (§2: the
		// download is rejected). too_large is for the bundle's own caps.
		return s.fail(yara.StateDownloadFailed, nil, err)
	}
	rules, results, err := s.o.Compiler.Compile(ctx, sources)
	if err != nil {
		return s.fail(yara.StateWorkerUnavailable, nil, fmt.Errorf("YARA: no worker could compile bundle %s: %w", short(b.Version), err))
	}
	for _, r := range results {
		if r.Error != "" {
			return s.fail(yara.StateCompileFailed, results, fmt.Errorf("YARA: ruleset %s r%d didn't compile; keeping the last good rules", r.ID, r.Revision))
		}
	}
	if err := s.o.Cache.Save(raw, b, sources); err != nil {
		log.Printf("YARA: could not cache bundle %s (applied anyway): %v", short(b.Version), err)
	}
	log.Printf("YARA: applying bundle %s (%d rulesets, %d rules)", short(b.Version), len(b.Rulesets), countRules(results))
	s.swap(&Active{Bundle: b, Rules: rules, Compiled: results}, results)
	return nil
}

// download gets every ruleset's source, from the cache when it already has
// that SHA-256, and checks size and SHA-256 against the bundle.
func (s *Syncer) download(ctx context.Context, b *yara.Bundle) ([]yara.RuleSource, error) {
	out := make([]yara.RuleSource, 0, len(b.Rulesets))
	for _, r := range b.Rulesets {
		if src, ok := s.o.Cache.Source(r.SHA256); ok && int64(len(src)) == r.Size {
			out = append(out, yara.RuleSource{ID: r.ID, Revision: r.Revision, Source: src})
			continue
		}
		var buf bytes.Buffer
		err := s.o.Retry(ctx, func() error {
			buf.Reset()
			return s.o.Downloader.DownloadRuleset(ctx, r.StoragePath, &buf, r.Size+1)
		})
		if err != nil {
			return nil, fmt.Errorf("YARA: download ruleset %s r%d: %w", r.ID, r.Revision, err)
		}
		sum := sha256.Sum256(buf.Bytes())
		if int64(buf.Len()) != r.Size || !strings.EqualFold(hex.EncodeToString(sum[:]), r.SHA256) {
			return nil, fmt.Errorf("YARA: ruleset %s r%d: size or SHA-256 doesn't match the bundle; rejected", r.ID, r.Revision)
		}
		out = append(out, yara.RuleSource{ID: r.ID, Revision: r.Revision, Source: buf.Bytes()})
	}
	return out, nil
}

// Restore applies the cached bundle now, if no Sync has yet. A yara-scan
// task that arrives right after startup calls it, so it scans with the
// rules the device already has instead of failing.
func (s *Syncer) Restore(ctx context.Context) {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	s.restoreOnce(ctx)
}

// restoreOnce runs the first-Sync work once; syncMu is held. A locally
// disabled agent deletes the cache instead.
func (s *Syncer) restoreOnce(ctx context.Context) {
	if s.restored {
		return
	}
	s.restored = true
	if s.o.LocallyDisabled {
		if err := s.o.Cache.Clear(); err != nil {
			log.Printf("YARA: could not delete the ruleset cache: %v", err)
		}
		return
	}
	s.restore(ctx)
}

// restore applies the cached bundle at startup, so scans work offline. A
// cache that can't be used is deleted; the poll then asks for the bundle
// from scratch.
func (s *Syncer) restore(ctx context.Context) {
	raw, err := s.o.Cache.LoadBundle()
	if err != nil || raw == nil {
		if err != nil {
			s.clearCorrupt(err)
		}
		return
	}
	b, err := yara.Decode(raw)
	if err != nil || !b.Enabled {
		s.clearCorrupt(fmt.Errorf("cached bundle unusable: %v", err))
		return
	}
	sources := make([]yara.RuleSource, 0, len(b.Rulesets))
	for _, r := range b.Rulesets {
		src, ok := s.o.Cache.Source(r.SHA256)
		if !ok || int64(len(src)) != r.Size {
			s.clearCorrupt(fmt.Errorf("cached source of ruleset %s missing or changed", r.ID))
			return
		}
		sources = append(sources, yara.RuleSource{ID: r.ID, Revision: r.Revision, Source: src})
	}
	rules, results, err := s.o.Compiler.Compile(ctx, sources)
	if err != nil {
		// No worker now: keep the cache, the poll applies the bundle again.
		log.Printf("YARA: cached bundle %s not loaded: %v", short(b.Version), err)
		return
	}
	for _, r := range results {
		if r.Error != "" {
			s.clearCorrupt(fmt.Errorf("cached ruleset %s doesn't compile", r.ID))
			return
		}
	}
	log.Printf("YARA: loaded cached bundle %s (%d rulesets)", short(b.Version), len(b.Rulesets))
	s.swap(&Active{Bundle: b, Rules: rules, Compiled: results}, results)
}

func (s *Syncer) clearCorrupt(err error) {
	log.Printf("YARA: deleting the ruleset cache: %v", err)
	if cerr := s.o.Cache.Clear(); cerr != nil {
		log.Printf("YARA: could not delete the ruleset cache: %v", cerr)
	}
}

// swap puts a in force and clears any failure.
func (s *Syncer) swap(a *Active, results []yara.CompileResult) {
	s.active.Store(a)
	s.mu.Lock()
	s.failState, s.failures, s.results = "", 0, results
	s.mu.Unlock()
	if s.o.OnChange != nil {
		s.o.OnChange(a)
	}
}

// fail records why the newest bundle isn't applied; the last good one stays.
func (s *Syncer) fail(state string, results []yara.CompileResult, err error) error {
	s.mu.Lock()
	s.failState = state
	s.failures++
	if results != nil {
		s.results = results
	}
	s.mu.Unlock()
	return err
}

// schedule sets the next poll: the interval plus jitter, or a backoff after
// a failure (1, 2, 4, ... minutes, at most the interval).
func (s *Syncer) schedule(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	wait := PollInterval + time.Duration(randInt63n(int64(pollJitter)))
	if err != nil || s.failState != "" {
		n := max(s.failures, 1)
		backoff := firstBackoff << min(n-1, 4)
		wait = min(backoff, PollInterval)
	}
	s.next = s.now().Add(max(wait, minPollGap))
}

// SetTCCDenied records whether the last scan was refused folders by macOS
// privacy (no Full Disk Access, #413); the status then says tcc_denied.
func (s *Syncer) SetTCCDenied(denied bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tccDenied = denied
}

// Status is what the device applied (p_status).
func (s *Syncer) Status() yara.Status {
	a := s.Active()
	s.mu.Lock()
	failState, results, lastScan, tcc := s.failState, s.results, s.lastScan, s.tccDenied
	s.mu.Unlock()
	st := yara.Status{
		AgentVersion:  s.o.AgentVersion,
		EngineVersion: s.o.EngineVersion,
		Rulesets:      []yara.RulesetStatus{},
		LastScan:      lastScan,
	}
	if a != nil && a.Bundle != nil {
		st.AppliedVersion = a.Bundle.Version
	}
	switch {
	case s.o.LocallyDisabled:
		st.State = yara.StateDisabled
	case failState != "":
		st.State = failState
	case !a.Enabled():
		st.State = yara.StateDisabled
	case s.o.WorkerHealthy != nil && !s.o.WorkerHealthy():
		st.State = yara.StateWorkerUnavailable
	case tcc:
		st.State = yara.StateTCCDenied
	default:
		st.State = yara.StateOK
	}
	for _, r := range results {
		st.Rulesets = append(st.Rulesets, r.RulesetStatus())
	}
	return st
}

func countRules(rs []yara.CompileResult) int {
	n := 0
	for _, r := range rs {
		n += r.Rules
	}
	return n
}

// short shortens a bundle version (a SHA-256) for logs.
func short(v string) string { return yara.Truncate(v, 12) }

// randInt63n returns a random int64 in [0, n), or 0 when n <= 0.
func randInt63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return int64(binary.BigEndian.Uint64(buf[:])>>1) % n
}
