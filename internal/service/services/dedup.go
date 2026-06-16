package services

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
	"sentinelgo/internal/models"
)

// svcsForceResendInterval is the maximum time between full services syncs even
// when the list has not changed.
const svcsForceResendInterval = 1 * time.Hour

var (
	svcsInProgress atomic.Bool
	svcsStateMu    sync.Mutex
	svcsLastHash   string
	svcsLastForce  time.Time
)

// SendByRPCIfChanged sends services data only when the list has changed since
// the last successful upload, or when svcsForceResendInterval has elapsed.
// Concurrent callers are dropped immediately (trylock semantics).
// Returns skipped=true when no upload was performed.
func (s *ServicesService) SendByRPCIfChanged(ctx context.Context, deviceID string, list []models.ServiceInfo, cfg *config.Config) (skipped bool, err error) {
	if !svcsInProgress.CompareAndSwap(false, true) {
		log.Printf("[services] sync already in progress, skipping concurrent call")
		return true, nil
	}
	defer svcsInProgress.Store(false)

	hash := hashServiceList(list)

	svcsStateMu.Lock()
	unchanged := hash == svcsLastHash && time.Now().Before(svcsLastForce.Add(svcsForceResendInterval))
	svcsStateMu.Unlock()

	if unchanged {
		log.Printf("[services] list unchanged since last sync, skipping upload")
		return true, nil
	}

	if err := s.SendByRPC(ctx, deviceID, list, cfg); err != nil {
		return false, err
	}

	svcsStateMu.Lock()
	svcsLastHash = hash
	svcsLastForce = time.Now()
	svcsStateMu.Unlock()
	return false, nil
}

// hashServiceList hashes the stable identity fields of each service, excluding
// volatile values (PID, FirstSeenAt, UpdatedAt) that change on every restart
// without representing a meaningful configuration change.
func hashServiceList(list []models.ServiceInfo) string {
	type entry struct {
		Name        string
		DisplayName string
		Status      string
		StartType   string
		Description string
		Source      string
		RunAs       string
	}
	entries := make([]entry, len(list))
	for i, s := range list {
		entries[i] = entry{
			Name:        s.Name,
			DisplayName: s.DisplayName,
			Status:      s.Status,
			StartType:   s.StartType,
			Description: s.Description,
			Source:      s.Source,
			RunAs:       s.RunAs,
		}
	}
	data, _ := json.Marshal(entries)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
