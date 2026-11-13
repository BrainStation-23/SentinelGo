package filedlp

// At-rest classification on Windows (#331 part 2): the runner (atrest.go)
// with its own scan worker at background CPU and IO priority, the USN
// journal (usn_windows.go), and the enforcer's glue.

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"

	"sentinelgo/internal/dlp/filescan"
	"sentinelgo/internal/dlp/policy"
	"sentinelgo/internal/dlp/scanworker"
	"sentinelgo/internal/yara/walk"
)

// atRestPoolOptions: one worker, separate from the destination scans'
// (which writes wait on), lowering its own priority.
func atRestPoolOptions(exe string) scanworker.Options {
	env := append([]string{scanworker.BackgroundEnv + "=1"}, workerEnv...)
	return scanworker.Options{Exe: exe, Workers: 1, Name: "DLP at-rest classification", Env: env}
}

// newAtRest sets up at-rest classification for e: the store in the config
// directory, and the decider's lookups into it. Without a config directory
// there is nowhere to keep verdicts, and it stays off.
func (e *windowsEnforcer) newAtRest() {
	if e.opts.ConfigDir == "" {
		return
	}
	store, err := openAtRestStore(filepath.Join(e.opts.ConfigDir, AtRestFile))
	if err != nil {
		log.Printf("DLP: %v (starting with an empty at-rest store)", err)
	}
	r := newAtRestRunner(store, atRestPoolScanner{e}, newUSNJournal(), "windows")
	r.compiled = e.compiled.Load
	r.localOff = e.localOff.Load
	r.mounts = externalWalkMounts
	r.open = openAtRest
	e.atRest = r
	e.decider.SetAtRest(store.lookup)
}

type atRestPoolScanner struct{ e *windowsEnforcer }

func (p atRestPoolScanner) Scan(ctx context.Context, f *os.File, size int64, timeout time.Duration) filescan.Result {
	pool := p.e.atRestPool.Load()
	if pool == nil {
		return filescan.Result{Status: filescan.Unscannable(scanworker.ReasonWorkerFailed), Size: size}
	}
	return pool.Scan(ctx, f, size, timeout)
}

// startAtRest starts the runner and its worker pool with the hook.
func (e *windowsEnforcer) startAtRest(ctx context.Context) {
	if e.atRest == nil {
		return
	}
	pool := scanworker.NewPool(atRestPoolOptions(e.opts.Exe))
	if c := e.compiled.Load(); c != nil {
		if raw, err := json.Marshal(c.Bundle); err == nil {
			pool.SetPolicy(raw)
		}
	}
	e.atRestPool.Store(pool)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		e.atRest.run(ctx)
	}()
}

// stopAtRest stops the worker pool once the runner has returned. When the
// policy no longer asks for classification, the verdicts are dropped too:
// the runner isn't there to do it.
func (e *windowsEnforcer) stopAtRest() {
	if pool := e.atRestPool.Swap(nil); pool != nil {
		pool.Stop()
	}
	if e.atRest == nil {
		return
	}
	if c := e.compiled.Load(); c == nil || !c.Modules.Files.WantsAtRest() {
		e.atRest.store.forget()
		if err := e.atRest.store.save(); err != nil {
			log.Printf("DLP: %v", err)
		}
	}
}

// applyAtRest hands a new policy to the worker and wakes the runner.
func (e *windowsEnforcer) applyAtRest(raw []byte) {
	if e.atRest == nil {
		return
	}
	if pool := e.atRestPool.Load(); pool != nil && raw != nil {
		pool.SetPolicy(raw)
	}
	e.atRest.poke()
}

// atRestCapability is CapAtRest's value under c.
func (e *windowsEnforcer) atRestCapability(c *policy.Compiled, state string) string {
	switch {
	case e.atRest == nil:
		return "unsupported:no_config_dir"
	case !c.Modules.Files.ClassifiesAtRest("windows"):
		return "unsupported:" + atRestNoTaint[len("off:"):]
	}
	var workers scanworker.Health
	if pool := e.atRestPool.Load(); pool != nil {
		workers = pool.Health()
	}
	return capability(state, workers)
}

// openAtRest opens a listed file without side effects (no link followed,
// no cloud download, last access time kept) and reads its identity, as the
// decider's source opener does, so the verdict is found again by identity.
func openAtRest(f walk.File) (*os.File, Identity, error) {
	fh, err := walk.Open(f)
	if err != nil {
		return nil, Identity{}, err
	}
	id, err := handleIdentity(windows.Handle(fh.Fd()))
	if err != nil {
		_ = fh.Close()
		return nil, Identity{}, err
	}
	return fh, id, nil
}

// externalWalkMounts lists removable drives and network shares, which
// classification never walks.
func externalWalkMounts() []walk.Mount {
	var out []walk.Mount
	for _, d := range ExternalMounts() {
		if d.Mount != "" {
			out = append(out, walk.Mount{Path: d.Mount, Network: d.Type == TypeNetworkShare})
		}
	}
	return out
}
