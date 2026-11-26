package internal

import (
	"context"
	"log"
	"runtime"

	"sentinelgo/internal/config"
	"sentinelgo/internal/scheduler"
	authsvc "sentinelgo/internal/service/auth"
	"sentinelgo/internal/supabase"
	"sentinelgo/internal/uninstallprotect"
)

// startUninstallProtection schedules the uninstall token sync (#566).
// Windows only: the console shows a device's token on Windows devices, and
// only the MSI runs the check. Both builds have it: it stops a removal and
// changes nothing on the device.
func (mi *MainIntegration) startUninstallProtection() {
	if runtime.GOOS != "windows" || mi.cfg.Path == "" {
		return
	}
	cfg := mi.cfg
	s := uninstallprotect.NewSyncer(
		func() uninstallprotect.RPC { return supabase.FromConfig(cfg) },
		uninstallprotect.Retrier(authRetrier(cfg, mi.authSvc)),
		uninstallprotect.StatePath(cfg.Path))
	err := mi.scheduler.AddTask(&scheduler.Task{
		Name:     "uninstall-protection-sync",
		Interval: uninstallprotect.TickInterval,
		Enabled:  true,
		Handler:  uninstallProtectionHandler(s),
	})
	if err != nil {
		log.Printf("Warning: uninstall protection sync not scheduled: %v", err)
	}
}

// uninstallProtectionHandler syncs unless the session is degraded (the
// token-refresh task recovers it).
func uninstallProtectionHandler(s *uninstallprotect.Syncer) scheduler.TaskHandler {
	return func(ctx context.Context, _ *config.Config, authSvc *authsvc.Service) error {
		if authSvc != nil && !authSvc.Healthy() {
			log.Printf("Scheduler: auth degraded, skipping uninstall-protection-sync until session recovers")
			return nil
		}
		return s.Tick(ctx)
	}
}
