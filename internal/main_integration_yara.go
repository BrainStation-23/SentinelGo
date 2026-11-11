package internal

import (
	"context"
	"log"
	"os"
	"path/filepath"

	"sentinelgo/internal/config"
	"sentinelgo/internal/dlp/scanworker"
	"sentinelgo/internal/scheduler"
	authsvc "sentinelgo/internal/service/auth"
	"sentinelgo/internal/supabase"
	"sentinelgo/internal/yara"
	"sentinelgo/internal/yara/engine"
	"sentinelgo/internal/yara/ruleset"
)

// yaraSyncTick is how often the yara-ruleset-sync task wakes up; the Syncer
// decides whether a poll is due (every 15 minutes, or sooner when pushed).
const yaraSyncTick = ruleset.PollInterval / 15

// yaraWorkers is the YARA pool's size: one worker, separate from file DLP's
// pool, so a long scan never starves DLP's blocking decisions (#412).
const yaraWorkers = 1

// startYARA schedules the ruleset sync (#411) and creates the YARA scan
// worker pool (#412). Workers start only when a bundle has rules to compile:
// the backend sends a disabled bundle to agents that don't advertise
// yara_scan_v1. Errors are logged, never fatal.
func (mi *MainIntegration) startYARA() {
	cfg := mi.cfg
	exe, err := os.Executable()
	if err != nil {
		log.Printf("Warning: YARA not started: %v", err)
		return
	}
	pool := scanworker.NewPool(scanworker.Options{Exe: exe, Workers: yaraWorkers, Name: "YARA scan"})
	client := ruleset.NewClient(func() ruleset.Supabase { return supabase.FromConfig(cfg) })
	s := ruleset.New(ruleset.Options{
		Fetcher:       client,
		Downloader:    client,
		Compiler:      poolCompiler{pool},
		Retry:         ruleset.Retrier(authRetrier(cfg, mi.authSvc)),
		Cache:         ruleset.NewCache(filepath.Join(filepath.Dir(cfg.Path), ruleset.DirName)),
		AgentVersion:  config.Version,
		EngineVersion: engine.EngineVersion(),
		WorkerHealthy: func() bool { return !pool.Health().Disabled },
	})
	err = mi.scheduler.AddTask(&scheduler.Task{
		Name:     yara.TaskSync,
		Interval: yaraSyncTick,
		Enabled:  true,
		Handler:  yaraSyncHandler(s),
	})
	if err != nil {
		log.Printf("Warning: YARA ruleset sync not scheduled: %v", err)
		pool.Stop()
		return
	}
	mi.yaraPool, mi.yaraSyncer = pool, s
}

// stopYARA kills the YARA workers (after the scheduler has stopped).
func (mi *MainIntegration) stopYARA() {
	if mi.yaraPool != nil {
		mi.yaraPool.Stop()
		mi.yaraPool = nil
	}
}

// yaraSyncHandler polls when due, unless the session is degraded (the
// token-refresh task recovers it). The Syncer wraps each server call in
// DoWithAuthRetry itself (Options.Retry).
func yaraSyncHandler(s *ruleset.Syncer) scheduler.TaskHandler {
	return func(ctx context.Context, _ *config.Config, authSvc *authsvc.Service) error {
		if !s.Due() {
			return nil
		}
		if authSvc != nil && !authSvc.Healthy() {
			log.Printf("Scheduler: auth degraded, skipping %s until session recovers", yara.TaskSync)
			return nil
		}
		return s.Sync(ctx)
	}
}

// poolCompiler compiles rule sources in a sandboxed YARA worker.
type poolCompiler struct{ pool *scanworker.Pool }

func (c poolCompiler) Compile(ctx context.Context, srcs []yara.RuleSource) (ruleset.Rules, []yara.CompileResult, error) {
	rules := scanworker.NewYARARules(srcs)
	res, err := c.pool.CompileYARA(ctx, rules)
	if err != nil {
		return nil, nil, err
	}
	return rules, res, nil
}
