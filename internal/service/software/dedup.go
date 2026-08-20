package software

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"sentinelgo/internal/config"
)

// swForceResendInterval is the maximum time between full software syncs even
// when the installed-software list has not changed. This ensures the backend
// receives a periodic refresh after a manual database fix or first registration.
const swForceResendInterval = 1 * time.Hour

var (
	// swInProgress is a trylock: if the scheduler's periodic task and a
	// remotely-dispatched task-manager task both try to run at the same time,
	// the second caller skips rather than sending a duplicate payload.
	swInProgress atomic.Bool
	swStateMu    sync.Mutex
	swLastHash   string
	swLastForce  time.Time
)

// SendByRPCIfChanged sends software data only when the installed-software list
// has changed since the last successful upload, or when swForceResendInterval
// has elapsed. Concurrent callers are dropped immediately (trylock semantics)
// to prevent the periodic scheduler and a remotely-dispatched task from sending
// two identical payloads at the same time.
// Returns skipped=true when no upload was performed.
func (s *SoftwareService) SendByRPCIfChanged(ctx context.Context, deviceID string, list []SoftwareInfo, cfg *config.Config) (skipped bool, err error) {
	return s.SendSnapshotByRPCIfChanged(ctx, deviceID, list, true, cfg)
}

// SendSnapshotByRPCIfChanged is the completeness-aware variant used by the
// scheduler and remote sync task. Completeness is included in the dedupe hash:
// transitioning from a partial scan to a complete scan must be uploaded even
// when the collected item list itself is unchanged.
func (s *SoftwareService) SendSnapshotByRPCIfChanged(ctx context.Context, _ string, list []SoftwareInfo, complete bool, cfg *config.Config) (skipped bool, err error) {
	if !swInProgress.CompareAndSwap(false, true) {
		log.Printf("[software] sync already in progress, skipping concurrent call")
		return true, nil
	}
	defer swInProgress.Store(false)

	hash := hashSoftwareSnapshot(list, complete)

	swStateMu.Lock()
	unchanged := hash == swLastHash && time.Now().Before(swLastForce.Add(swForceResendInterval))
	swStateMu.Unlock()

	if unchanged {
		log.Printf("[software] list unchanged since last sync, skipping upload")
		return true, nil
	}

	if err := s.SendSnapshotByRPC(ctx, list, complete, cfg); err != nil {
		return false, err
	}

	swStateMu.Lock()
	swLastHash = hash
	swLastForce = time.Now()
	swStateMu.Unlock()
	return false, nil
}

func hashSoftwareSnapshot(list []SoftwareInfo, complete bool) string {
	data, _ := json.Marshal(struct {
		Complete bool           `json:"complete"`
		Items    []SoftwareInfo `json:"items"`
	}{Complete: complete, Items: list})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
