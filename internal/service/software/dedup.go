package software

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"sentinelgo/internal/config"
)

// DefaultForceResendInterval is the maximum time between full software syncs
// even when the installed-software list has not changed. It guarantees the
// backend receives a periodic refresh after a manual database fix or a first
// registration.
//
// Raised from one hour to a day. The hourly figure existed to compensate for a
// fingerprint so unstable that "unchanged" was nearly unreachable (see
// stableSoftwareFingerprint); with the fingerprint fixed, an unchanged list
// genuinely stays unchanged, and re-sending an identical inventory 24 times a
// day per endpoint is pure backend load. Across 10,000 endpoints this removes
// roughly 230,000 uploads of unchanged data per day.
const DefaultForceResendInterval = 24 * time.Hour

// DefaultCollectInterval is how often the installed-software list is actually
// scanned.
//
// The scan is genuinely expensive — registry enumeration across every loaded
// user hive, Get-AppxPackage -AllUsers, system_profiler at 1.5–4 s,
// dpkg/rpm/snap/flatpak, and browser-extension filesystem walks across all user
// homes. At the previous five-minute cadence that was 288 full scans per device
// per day, about 2.9 million per day across 10,000 endpoints, for data that
// changes a few times a week. Six hours keeps a deployment visible the same
// working day while cutting the scan count by a factor of 72; an immediate
// refresh after a deployment is already available through the on-demand
// sync-software remote task, which bypasses this interval entirely.
const DefaultCollectInterval = 6 * time.Hour

var (
	// swInProgress is a trylock: if the scheduler's periodic task and a
	// remotely-dispatched task-manager task both try to run at the same time,
	// the second caller skips rather than sending a duplicate payload.
	swInProgress atomic.Bool
	swStateMu    sync.Mutex
	swLastHash   string
	swLastForce  time.Time
	// swLastCollect is when the expensive scan last ran. Zero until the first
	// scan, so a freshly started agent always collects immediately rather than
	// waiting out an interval — first registration must not be delayed by hours.
	swLastCollect time.Time
)

// ShouldCollect reports whether the expensive software scan is due, and records
// the decision when it is.
//
// It gates collection rather than upload. Deduplication already prevented
// unchanged data from being SENT, but the scan itself ran every cycle
// regardless, and the scan is what costs the endpoint. Callers that must scan
// immediately — the on-demand sync-software task and the debug CLI — simply do
// not call this.
//
// A non-positive interval means "no gate", preserving the previous
// scan-every-cycle behaviour for anyone who explicitly configures it.
func ShouldCollect(interval time.Duration) bool {
	if interval <= 0 {
		return true
	}

	swStateMu.Lock()
	defer swStateMu.Unlock()

	if !swLastCollect.IsZero() && time.Since(swLastCollect) < interval {
		return false
	}
	swLastCollect = time.Now()
	return true
}

// resetSyncState clears the package-level dedupe and cadence state. Test-only:
// the state is process-global by design, so tests that exercise consecutive
// cycles must be able to start from a known point.
func resetSyncState() {
	swStateMu.Lock()
	defer swStateMu.Unlock()
	swLastHash = ""
	swLastForce = time.Time{}
	swLastCollect = time.Time{}
}

// SendByRPCIfChanged sends software data only when the installed-software list
// has changed since the last successful upload, or when the force-resend
// interval has elapsed. Concurrent callers are dropped immediately (trylock semantics)
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
	resend := DefaultForceResendInterval
	if cfg != nil && cfg.GetSoftwareResendInterval() > 0 {
		resend = cfg.GetSoftwareResendInterval()
	}

	swStateMu.Lock()
	unchanged := hash == swLastHash && time.Now().Before(swLastForce.Add(resend))
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

// stableFields is the projection of SoftwareInfo that the dedupe fingerprint
// hashes: the fields that identify an installed application, and nothing that
// moves on its own.
//
// Two SoftwareInfo fields are deliberately absent, and both of them defeated
// deduplication entirely before this projection existed:
//
//   - LastOpened is usage metadata. Opening any single application on the
//     device changed it, which changed the hash of the WHOLE list, which forced
//     a full re-upload of the entire installed-software inventory. A user
//     launching a browser is not a change to what is installed.
//   - FirstSeenAt is worse. On macOS it falls back to time.Now() whenever an
//     application exposes no LastModified date (collect_darwin.go), so for those
//     entries it was a different value on every single scan — the list could
//     never hash equal, and "unchanged" was unreachable.
//
// This mirrors hashServiceList in the sibling services package, which excludes
// its own volatile fields (PID, FirstSeenAt, UpdatedAt) for exactly this reason.
// Payload content is unaffected: both fields are still collected and still
// uploaded. What is sent and what decides whether to send are separate concerns.
type stableFields struct {
	Name             string
	Source           string
	InstalledVersion string
	Type             string
	DisplayName      string
	SoftwarePackage  string
	AppStoreApp      string
	FilePath         string
}

// stableSoftwareFingerprint projects and sorts the list so an unchanged
// inventory hashes identically across cycles.
//
// Sorting matters as much as the field selection. The list is assembled by
// walking registry hives, package managers and user home directories, none of
// which guarantee a stable enumeration order between runs; the same installed
// set arriving in a different order would hash differently and re-upload.
func stableSoftwareFingerprint(list []SoftwareInfo) []stableFields {
	out := make([]stableFields, 0, len(list))
	for _, sw := range list {
		out = append(out, stableFields{
			Name:             sw.Name,
			Source:           sw.Source,
			InstalledVersion: sw.InstalledVersion,
			Type:             sw.Type,
			DisplayName:      sw.DisplayName,
			SoftwarePackage:  sw.SoftwarePackage,
			AppStoreApp:      sw.AppStoreApp,
			FilePath:         sw.FilePath,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.InstalledVersion != b.InstalledVersion {
			return a.InstalledVersion < b.InstalledVersion
		}
		return a.FilePath < b.FilePath
	})
	return out
}

func hashSoftwareSnapshot(list []SoftwareInfo, complete bool) string {
	data, _ := json.Marshal(struct {
		Complete bool           `json:"complete"`
		Items    []stableFields `json:"items"`
	}{Complete: complete, Items: stableSoftwareFingerprint(list)})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
