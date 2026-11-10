package native

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"sentinelgo/internal/config"
	pkgsvc "sentinelgo/internal/service/packages"
	"sentinelgo/internal/taskstore"
)

// PackageSync collects the npm, PyPI and Composer packages now and uploads a
// full inventory (#421). The service registers it at startup.
type PackageSync func(ctx context.Context) (pkgsvc.Result, error)

var (
	packageSyncMu sync.RWMutex
	packageSync   PackageSync
)

// SetPackageSync installs (or with nil removes) the hook sync-packages calls.
func SetPackageSync(f PackageSync) {
	packageSyncMu.Lock()
	defer packageSyncMu.Unlock()
	packageSync = f
}

// errPackagesNotRunning is the result when the service hasn't started the
// package inventory (e.g. a CLI run).
var errPackagesNotRunning = errors.New("package inventory is not running in this agent process")

// syncPackagesHandler re-collects the package inventory on demand, like
// sync-software.
type syncPackagesHandler struct{}

func init() { Register(&syncPackagesHandler{}) }

func (h *syncPackagesHandler) Slugs() []string {
	return []string{"sync-packages"}
}

func (h *syncPackagesHandler) Run(ctx context.Context, _ *config.Config, _ taskstore.Task) (string, error) {
	packageSyncMu.RLock()
	f := packageSync
	packageSyncMu.RUnlock()
	if f == nil {
		return "", errPackagesNotRunning
	}
	res, err := f(ctx)
	if err != nil {
		return "", fmt.Errorf("sync-packages: %w", err)
	}
	if !res.Enabled {
		return "package inventory is turned off for this organisation; nothing collected", nil
	}
	msg := fmt.Sprintf("packages synced: %d packages in %d upload(s)", res.Packages, res.Parts)
	if !res.Complete {
		msg += " (some locations could not be read; nothing was retired)"
	}
	return msg, nil
}
