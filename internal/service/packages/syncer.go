package packages

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"sync"
	"sync/atomic"
	"time"
)

// Timing of the package-sync scheduler task.
const (
	// TickInterval is how often the scheduler calls Tick. Each tick polls
	// the settings, so a change in the console is picked up within it.
	TickInterval = 15 * time.Minute
	// collectInterval is how often packages are collected. Reading every
	// global install folder is cheap, but there's no need to do it more
	// often: package installs are rare compared with the software list.
	collectInterval = 6 * time.Hour
	// resumeInterval is how soon a project scan pass that didn't fit in
	// one run continues.
	resumeInterval = TickInterval
	// resendInterval forces an upload of an unchanged inventory, so the
	// server's view recovers from a lost upload or a database fix.
	resendInterval = 24 * time.Hour
	// firstCollectSpread spreads the first collection after a start over
	// this window, so a fleet updating at once doesn't scan at once.
	firstCollectSpread = 30 * time.Minute
)

// ErrBusy is returned when another collection is running.
var ErrBusy = errors.New("package sync already running")

// SettingsFetcher polls the server's settings (Client.FetchSettings).
type SettingsFetcher interface {
	FetchSettings(ctx context.Context, knownVersion string) (Settings, bool, error)
}

// Collection is what one collection run found.
type Collection struct {
	Packages []Package
	// Complete is false when part of the inventory couldn't be read, so it
	// must not retire packages the run didn't see.
	Complete bool
	// More is true when a project scan pass has work left for the next run.
	More bool
}

// Collector collects the inventory a run reports.
type Collector func(ctx context.Context, s Settings) Collection

// DefaultCollector collects global installs and, when the settings turn
// project scanning on, the lockfiles under the project roots.
func DefaultCollector() Collector {
	projects := newProjectScanner()
	return func(ctx context.Context, s Settings) Collection {
		pkgs, complete := CollectGlobal(ctx)
		if !s.ProjectScan {
			projects.reset()
			return Collection{Packages: pkgs, Complete: complete}
		}
		proj, projComplete, more := projects.run(ctx, s)
		return Collection{Packages: append(pkgs, proj...), Complete: complete && projComplete, More: more}
	}
}

// Retrier runs one server call, recovering an expired session once
// (auth.Service.DoWithAuthRetry in production).
type Retrier func(ctx context.Context, fn func() error) error

// Result describes one sync.
type Result struct {
	// Enabled is false when the server has package inventory turned off.
	Enabled bool
	// Packages is the number of packages collected.
	Packages int
	// Parts is the number of uploads; 0 when nothing was sent.
	Parts int
	// Unchanged is true when the inventory matched the last upload.
	Unchanged bool
	// Complete is false when part of the inventory couldn't be read.
	Complete bool
}

// Syncer keeps the device's package inventory on the server: it polls the
// settings, collects when due and uploads what changed.
type Syncer struct {
	fetch   SettingsFetcher
	enqueue Enqueuer
	collect Collector
	retry   Retrier
	now     func() time.Time

	running atomic.Bool

	mu          sync.Mutex
	settings    Settings
	known       bool // settings were fetched at least once
	nextCollect time.Time
	lastHash    string
	lastSent    time.Time
}

// NewSyncer returns a Syncer. collect nil means DefaultCollector; retry nil
// calls fn directly.
func NewSyncer(fetch SettingsFetcher, enqueue Enqueuer, collect Collector, retry Retrier) *Syncer {
	if collect == nil {
		collect = DefaultCollector()
	}
	if retry == nil {
		retry = func(_ context.Context, fn func() error) error { return fn() }
	}
	s := &Syncer{fetch: fetch, enqueue: enqueue, collect: collect, retry: retry, now: time.Now}
	s.nextCollect = s.now().Add(randDuration(firstCollectSpread))
	return s
}

// Tick is the scheduler task: poll the settings, then collect and upload if
// a collection is due or the settings changed. A failed settings poll keeps
// the last settings.
func (s *Syncer) Tick(ctx context.Context) error {
	changed, pollErr := s.pollSettings(ctx)
	s.mu.Lock()
	settings, known := s.settings, s.known
	due := changed || !s.now().Before(s.nextCollect)
	s.mu.Unlock()
	if !known || !settings.Enabled || !due {
		return pollErr
	}
	_, err := s.run(ctx, settings, false)
	if errors.Is(err, ErrBusy) {
		err = nil // the running sync covers this tick
	}
	return errors.Join(pollErr, err)
}

// SyncNow is the sync-packages task: fetch the settings, collect and upload
// a full inventory even if it hasn't changed.
func (s *Syncer) SyncNow(ctx context.Context) (Result, error) {
	if _, err := s.pollSettings(ctx); err != nil {
		s.mu.Lock()
		known := s.known
		s.mu.Unlock()
		if !known {
			return Result{}, fmt.Errorf("fetch package settings: %w", err)
		}
		log.Printf("[packages] settings poll failed, using the last settings: %v", err)
	}
	s.mu.Lock()
	settings := s.settings
	s.mu.Unlock()
	if !settings.Enabled {
		return Result{}, nil
	}
	return s.run(ctx, settings, true)
}

// pollSettings fetches the settings and reports whether they changed.
func (s *Syncer) pollSettings(ctx context.Context) (changed bool, err error) {
	s.mu.Lock()
	known := s.settings.Version
	s.mu.Unlock()
	var got Settings
	err = s.retry(ctx, func() error {
		var ferr error
		got, changed, ferr = s.fetch.FetchSettings(ctx, known)
		return ferr
	})
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		return false, fmt.Errorf("fetch package settings: %w", err)
	}
	// With no known version the server always answers changed, so the
	// first successful poll always sets the settings.
	s.known = true
	if changed {
		if got.Enabled != s.settings.Enabled || got.ProjectScan != s.settings.ProjectScan {
			log.Printf("[packages] settings: enabled=%v project_scan=%v", got.Enabled, got.ProjectScan)
		}
		s.settings = got
	}
	return changed, nil
}

// run collects and uploads. force uploads even an unchanged inventory.
func (s *Syncer) run(ctx context.Context, settings Settings, force bool) (Result, error) {
	if !s.running.CompareAndSwap(false, true) {
		return Result{}, ErrBusy
	}
	defer s.running.Store(false)

	c := s.collect(ctx, settings)
	complete := c.Complete
	pkgs, invalid := normalize(c.Packages)
	if invalid > 0 {
		log.Printf("[packages] skipped %d packages the server would reject (empty or over-long fields)", invalid)
	}
	res := Result{Enabled: true, Packages: len(pkgs), Complete: complete}

	s.mu.Lock()
	s.nextCollect = s.now().Add(collectInterval)
	if c.More {
		s.nextCollect = s.now().Add(resumeInterval)
	}
	hash := hashPackages(pkgs, complete)
	unchanged := hash == s.lastHash && s.now().Before(s.lastSent.Add(resendInterval))
	s.mu.Unlock()

	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	if (unchanged && !force) || (!complete && len(pkgs) == 0) {
		res.Unchanged = unchanged
		return res, nil
	}

	sentAt := s.now()
	err := s.retry(ctx, func() error {
		n, serr := send(ctx, s.enqueue, pkgs, complete, sentAt)
		res.Parts = n
		return serr
	})
	if err != nil {
		return res, err
	}
	s.mu.Lock()
	s.lastHash, s.lastSent = hash, sentAt
	s.mu.Unlock()
	log.Printf("[packages] uploaded %d packages in %d part(s) (complete=%v)", res.Packages, res.Parts, complete)
	return res, nil
}

// hashPackages fingerprints a normalized (sorted) inventory.
func hashPackages(pkgs []Package, complete bool) string {
	h := sha256.New()
	enc := json.NewEncoder(h)
	_ = enc.Encode(complete)
	for _, p := range pkgs {
		_ = enc.Encode(p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// randDuration returns a random duration in [0, max).
func randDuration(maxD time.Duration) time.Duration {
	if maxD <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxD)))
	if err != nil {
		return maxD / 2
	}
	return time.Duration(n.Int64())
}
