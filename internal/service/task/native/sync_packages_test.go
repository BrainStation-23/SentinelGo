package native

import (
	"context"
	"errors"
	"strings"
	"testing"

	pkgsvc "sentinelgo/internal/service/packages"
	"sentinelgo/internal/taskstore"
)

func runSyncPackages(t *testing.T, f PackageSync) (string, error) {
	t.Helper()
	SetPackageSync(f)
	t.Cleanup(func() { SetPackageSync(nil) })
	h := Find("sync-packages")
	if h == nil {
		t.Fatal("sync-packages is not registered")
	}
	return h.Run(context.Background(), nil, taskstore.Task{})
}

func TestSyncPackages_NotRunning(t *testing.T) {
	if _, err := runSyncPackages(t, nil); !errors.Is(err, errPackagesNotRunning) {
		t.Errorf("err = %v, want errPackagesNotRunning", err)
	}
}

func TestSyncPackages_Disabled(t *testing.T) {
	out, err := runSyncPackages(t, func(context.Context) (pkgsvc.Result, error) { return pkgsvc.Result{}, nil })
	if err != nil || !strings.Contains(out, "turned off") {
		t.Errorf("Run = %q, %v", out, err)
	}
}

func TestSyncPackages_Synced(t *testing.T) {
	out, err := runSyncPackages(t, func(context.Context) (pkgsvc.Result, error) {
		return pkgsvc.Result{Enabled: true, Packages: 12, Parts: 1, Complete: true}, nil
	})
	if err != nil || out != "packages synced: 12 packages in 1 upload(s)" {
		t.Errorf("Run = %q, %v", out, err)
	}

	out, _ = runSyncPackages(t, func(context.Context) (pkgsvc.Result, error) {
		return pkgsvc.Result{Enabled: true, Packages: 2, Parts: 1}, nil
	})
	if !strings.Contains(out, "could not be read") {
		t.Errorf("incomplete Run = %q", out)
	}
}

func TestSyncPackages_Error(t *testing.T) {
	boom := errors.New("boom")
	_, err := runSyncPackages(t, func(context.Context) (pkgsvc.Result, error) { return pkgsvc.Result{}, boom })
	if !errors.Is(err, boom) {
		t.Errorf("err = %v", err)
	}
}
