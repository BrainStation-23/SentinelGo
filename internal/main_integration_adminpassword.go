package internal

import (
	"context"
	"log"
	"path/filepath"
	"runtime"

	"sentinelgo/internal/adminpassword"
	"sentinelgo/internal/config"
	"sentinelgo/internal/scheduler"
	authsvc "sentinelgo/internal/service/auth"
	"sentinelgo/internal/service/task/native"
	"sentinelgo/internal/supabase"
)

// startAdminPassword schedules local admin password rotation (#361). Windows
// only. It polls every 15 minutes and stays idle until the server sends an
// enabled policy (or while the server lacks the RPCs). The kill switch
// admin_password_rotation_enabled: false keeps it reporting "disabled".
func (mi *MainIntegration) startAdminPassword() {
	if runtime.GOOS != "windows" {
		return
	}
	cfg := mi.cfg
	client := adminpassword.NewClient(func() adminpassword.RPC { return supabase.FromConfig(cfg) })
	retry := authRetrier(cfg, mi.authSvc)
	r := adminpassword.New(adminpassword.Options{
		Server:          client,
		Host:            adminpassword.NewHost(),
		Retry:           adminpassword.Retrier(retry),
		StatePath:       filepath.Join(filepath.Dir(cfg.Path), adminpassword.StateFileName),
		LocallyDisabled: !cfg.AdminPasswordRotationEnabled,
	})
	if !cfg.AdminPasswordRotationEnabled {
		log.Printf("Admin password: rotation disabled on this device (admin_password_rotation_enabled=false); reporting state disabled")
	}
	err := mi.scheduler.AddTask(&scheduler.Task{
		Name:     "admin-password-rotation",
		Interval: adminpassword.TickInterval,
		Enabled:  true,
		Handler:  adminPasswordHandler(r),
	})
	if err != nil {
		log.Printf("Warning: admin password rotation not scheduled: %v", err)
		return
	}
	native.SetAdminPasswordRotator(r.RotateNow)
}

// adminPasswordHandler runs one tick unless the session is degraded (the
// token-refresh task recovers it). Nothing rotates without the server: the
// escrow comes first.
func adminPasswordHandler(r *adminpassword.Rotator) scheduler.TaskHandler {
	return func(ctx context.Context, _ *config.Config, authSvc *authsvc.Service) error {
		if authSvc != nil && !authSvc.Healthy() {
			log.Printf("Scheduler: auth degraded, skipping admin-password-rotation until session recovers")
			return nil
		}
		return r.Tick(ctx)
	}
}
