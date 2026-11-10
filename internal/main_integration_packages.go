package internal

import (
	"context"
	"log"

	"sentinelgo/internal/config"
	"sentinelgo/internal/scheduler"
	authsvc "sentinelgo/internal/service/auth"
	pkgsvc "sentinelgo/internal/service/packages"
	"sentinelgo/internal/service/task/native"
	"sentinelgo/internal/supabase"
)

// startPackageSync schedules the npm/PyPI/Composer inventory (#421) and
// installs the sync-packages task hook. The server decides whether anything
// is collected (off by default), so the task always runs and only polls the
// settings until an admin turns it on.
func (mi *MainIntegration) startPackageSync() {
	cfg := mi.cfg
	client := pkgsvc.NewClient(func() pkgsvc.RPC { return supabase.FromConfig(cfg) })
	s := pkgsvc.NewSyncer(client, client, nil, authRetrier(cfg, mi.authSvc))
	err := mi.scheduler.AddTask(&scheduler.Task{
		Name:     "package-sync",
		Interval: pkgsvc.TickInterval,
		Enabled:  true,
		Handler:  packageSyncHandler(s),
	})
	if err != nil {
		log.Printf("Warning: package inventory not scheduled: %v", err)
		return
	}
	native.SetPackageSync(s.SyncNow)
}

// packageSyncHandler runs one package-sync tick unless the session is
// degraded (the token-refresh task recovers it).
func packageSyncHandler(s *pkgsvc.Syncer) scheduler.TaskHandler {
	return func(ctx context.Context, _ *config.Config, authSvc *authsvc.Service) error {
		if authSvc != nil && !authSvc.Healthy() {
			log.Printf("Scheduler: auth degraded, skipping package-sync until session recovers")
			return nil
		}
		return s.Tick(ctx)
	}
}

// authRetrier wraps each server call in DoWithAuthRetry, so a 401 recovers
// the session once.
func authRetrier(cfg *config.Config, authSvc *authsvc.Service) pkgsvc.Retrier {
	return func(ctx context.Context, fn func() error) error {
		if authSvc == nil {
			return fn()
		}
		return authSvc.DoWithAuthRetry(ctx, cfg, fn)
	}
}
