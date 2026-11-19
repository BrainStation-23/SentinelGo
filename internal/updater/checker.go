package updater

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sync"
	"time"

	"sentinelgo/internal/buildflavor"
	"sentinelgo/internal/config"
	"sentinelgo/internal/httpx"
	"sentinelgo/internal/sanitize"
	"sentinelgo/internal/supabase"
)

// LatestRelease is the row returned by the get_latest_agent_release RPC.
type LatestRelease struct {
	Version     string    `json:"version"`
	PublishedAt time.Time `json:"published_at"`
	AssetName   string    `json:"asset_name"`
	AssetPath   string    `json:"asset_path"` // e.g. "v1.4.2/sentinelgo-linux-amd64"
	SHA256      string    `json:"sha256"`
	Size        int64     `json:"size"`
	ContentType string    `json:"content_type"`
	// AllowDowngrade is set by the server only during an admin-initiated
	// rollback: install Version even though it is older than the running
	// one. Missing (older servers) means false.
	AllowDowngrade bool `json:"allow_downgrade"`
	// Flavor is the build the returned asset is, "full" or "readonly"
	// (#548): the one the server assigned this device. Missing (an older
	// server) means this agent's own build, so nothing changes.
	Flavor string `json:"flavor"`
}

var updateMutex sync.Mutex

// AuthRetrier recovers the session on a 401 and retries once. It is satisfied
// by *auth.Service; kept as a local interface so the updater does not import
// the auth package.
type AuthRetrier interface {
	DoWithAuthRetry(ctx context.Context, cfg *config.Config, fn func() error) error
}

var (
	retrierMu sync.RWMutex
	retrier   AuthRetrier
)

// SetAuthRetrier lets every update path (startup check, scheduled auto-update,
// agent-update task) recover an expired token instead of failing until the
// next token refresh. Without one, Supabase calls are made once, as before.
func SetAuthRetrier(r AuthRetrier) {
	retrierMu.Lock()
	defer retrierMu.Unlock()
	retrier = r
}

// withAuthRetry runs fn through the configured AuthRetrier, if any.
func withAuthRetry(ctx context.Context, cfg *config.Config, fn func() error) error {
	retrierMu.RLock()
	r := retrier
	retrierMu.RUnlock()
	if r == nil {
		return fn()
	}
	return r.DoWithAuthRetry(ctx, cfg, fn)
}

// windowsServiceName is the SCM service name registered at install time
// (see cmd/sentinelgo/main.go). The Windows update path restarts via SCM
// because a running .exe cannot be replaced in place.
const windowsServiceName = "SentinelGo"

// rpcTimeout caps the release-discovery RPC so a hung connection cannot block
// the update path indefinitely while holding updateMutex.
const releaseRPCTimeout = 30 * time.Second

// connectivityClient is a short-timeout client used only for connectivity probes.
var connectivityClient = httpx.NewClient(10 * time.Second)

// Test seams: restart exits the process and dialTimeout reaches real hosts on
// port 443, so tests swap these for fakes.
var (
	restartFn       = restart
	dialTimeout     = net.DialTimeout
	spawnWatchdogFn = spawnWatchdog
)

// CheckAndApply checks for a newer release via Supabase RPC and applies the
// update if one is available.
//
// Order of operations is deliberate:
//  1. Compare against the COMPILED-IN running version (config.Version), not the
//     persisted cfg.CurrentVersion.
//  2. Only update on a strictly-newer semantic version, or an older one the
//     server explicitly approved (allow_downgrade, an audited rollback).
//     Equal versions are a no-op.
//  3. Require a SHA256 checksum (from RPC) and an ed25519 signature (from Storage).
//  4. Download and verify BEFORE replacing anything.
//  5. Replace + restart via the OS service manager.
func CheckAndApply(ctx context.Context, cfg *config.Config) error {
	updateMutex.Lock()
	defer updateMutex.Unlock()

	latest, err := fetchLatestRelease(ctx, cfg)
	if err != nil {
		return fmt.Errorf("fetch latest release: %w", err)
	}
	if latest == nil {
		log.Println("Updater: no release configured in Supabase yet, skipping")
		return nil
	}

	running := config.Version
	// A row whose asset isn't the build it names (or, from a server without
	// the flavor column, another build's asset: a read-only agent never
	// takes the full build that way) is refused, but only when it would be
	// installed: up to date or a dev build is still a quiet no-op.
	flavor, flavorErr := releaseFlavor(latest)
	if flavorErr != nil {
		flavor = buildflavor.Flavor
	}
	action, err := decideRelease(latest.Version, running, latest.AllowDowngrade, flavor)
	if err == nil && action != actionNone && flavorErr != nil {
		return flavorErr
	}
	if err != nil {
		// Cannot compare versions (e.g. a "dev" build). Skip.
		fmt.Printf("Skipping update: cannot compare versions (%v)\n", err)
		return nil
	}
	if action == actionNone {
		fmt.Printf("Already up to date (running %s, latest %s)\n",
			sanitize.ForLog(running), sanitize.ForLog(latest.Version))
		return nil
	}

	if heldBack(cfg, latest.Version) {
		return nil
	}

	if latest.SHA256 == "" {
		return fmt.Errorf("refusing to update to %s: no SHA256 in release manifest",
			sanitize.ForLog(latest.Version))
	}

	switch action {
	case actionDowngrade:
		log.Printf("Rolling back: %s -> %s (server-approved downgrade)",
			sanitize.ForLog(running), sanitize.ForLog(latest.Version))
	case actionSwitch:
		log.Printf("Switching build: %s -> %s at %s (assigned by the server)",
			buildflavor.Flavor, flavor, sanitize.ForLog(latest.Version))
	default:
		fmt.Printf("Found update: %s -> %s\n", sanitize.ForLog(running), sanitize.ForLog(latest.Version))
		if flavor != buildflavor.Flavor {
			log.Printf("Switching build: %s -> %s (assigned by the server)", buildflavor.Flavor, flavor)
		}
	}

	backupPath, err := createBackup()
	if err != nil {
		return fmt.Errorf("refusing to update without a backup: %w", err)
	}
	fmt.Printf("Created backup: %s\n", backupPath)

	// sig is stored alongside the binary with a .sig suffix, mirroring GitHub releases.
	sigAssetPath := latest.AssetPath + ".sig"

	newPath, actualChecksum, err := downloadAndVerify(ctx, cfg, latest.AssetPath, latest.SHA256, sigAssetPath)
	if err != nil {
		_ = removeFile(backupPath)
		return fmt.Errorf("download and verify failed: %w", err)
	}
	if actualChecksum != latest.SHA256 {
		_ = removeFile(newPath)
		_ = removeFile(backupPath)
		return fmt.Errorf("checksum mismatch: expected %s, got %s", latest.SHA256, actualChecksum)
	}

	// For an upgrade or a switch of build the backup stays until the new
	// binary proves healthy; a watchdog restores it otherwise (#503). A
	// server-approved downgrade goes to an earlier release, which may predate
	// the health check and could never confirm itself, so it isn't watched.
	var marker *Marker
	var markerPath string
	if action == actionUpgrade || action == actionSwitch {
		if marker, markerPath, err = startHealthWatch(cfg, running, latest.Version, flavor, backupPath); err != nil {
			_ = removeFile(newPath)
			_ = removeFile(backupPath)
			return err
		}
	}

	if runtime.GOOS != "windows" {
		if err := atomicReplace(newPath); err != nil {
			if marker != nil {
				endHealthWatch(marker, markerPath)
			}
			if rbErr := rollbackFromBackup(backupPath); rbErr != nil {
				return fmt.Errorf("atomic replace failed (%v) and rollback failed: %w", err, rbErr)
			}
			_ = removeFile(backupPath)
			return fmt.Errorf("atomic replace failed, rolled back to previous version: %w", err)
		}
	}

	if marker == nil {
		fmt.Printf("Update verified and staged: %s -> %s\n", running, latest.Version)
		_ = removeFile(backupPath)
		return restartFn(newPath)
	}

	fmt.Printf("Update verified and staged: %s -> %s (backup kept until it is healthy)\n", running, latest.Version)
	return restartFn(newPath)
}

// startHealthWatch writes the update marker and starts the watchdog, before
// the binary is touched: a new binary that can't start can't start a
// watchdog either, so without one nothing would roll it back. On error
// nothing is left behind and the update must not go ahead.
func startHealthWatch(cfg *config.Config, running, to, toFlavor, backupPath string) (*Marker, string, error) {
	marker, markerPath, err := beginHealthWatch(cfg, running, to, toFlavor, backupPath, time.Now())
	if err != nil {
		return nil, "", fmt.Errorf("refusing to update without a health check: %w", err)
	}
	if err := spawnWatchdogFn(marker, markerPath); err != nil {
		endHealthWatch(marker, markerPath)
		return nil, "", fmt.Errorf("refusing to update: the update watchdog didn't start: %w", err)
	}
	registerBoot(marker, markerPath) // the running watchdog doesn't survive a reboot (#516)
	return marker, markerPath, nil
}

// heldBack reports whether the update health check (#503) holds this
// version back: it was rolled back on this device, or an earlier update is
// still waiting for its health check.
func heldBack(cfg *config.Config, version string) bool {
	if rolledBack(cfg, version, time.Now()) {
		log.Printf("Updater: skipping %s: it was rolled back on this device after failing its health check; waiting for another version",
			sanitize.ForLog(version))
		return true
	}
	if m, pending := pendingUpdate(cfg, time.Now()); pending {
		log.Printf("Updater: update %s -> %s is still waiting for its health check; not updating again yet",
			sanitize.ForLog(m.FromVersion), sanitize.ForLog(m.ToVersion))
		return true
	}
	return false
}

// CheckAndApplyWithRetry performs an update check and apply with exponential
// backoff retry. Backoff starts at 5 s and caps at 5 min.
func CheckAndApplyWithRetry(ctx context.Context, cfg *config.Config) error {
	const maxAttempts = 3
	var lastErr error

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			wait := backoffDuration(attempt - 1)
			log.Printf("Update attempt %d/%d after %s backoff", attempt+1, maxAttempts, wait)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}

		err := CheckAndApply(ctx, cfg)
		if err == nil {
			return nil
		}

		lastErr = err
		log.Printf("Update attempt %d/%d failed: %v", attempt+1, maxAttempts, err)
	}

	return fmt.Errorf("update failed after %d attempts: %w", maxAttempts, lastErr)
}

// backoffDuration returns the wait duration for retry attempt n (0-indexed).
// Doubles from 5 s, capped at 5 min.
func backoffDuration(n int) time.Duration {
	d := 5 * time.Second * (1 << uint(n))
	if d > 5*time.Minute {
		d = 5 * time.Minute
	}
	return d
}

// fetchLatestRelease calls the get_latest_agent_release RPC and returns the
// result, or nil when no release is configured yet. The platform and arch are
// derived from runtime.GOOS / runtime.GOARCH.
//
// The HTTP status is checked (postgrest-go did not, so a 401 or 500 surfaced
// as a JSON parse error), and an expired token is recovered via the
// AuthRetrier, so an agent can still self-update after its token expires.
func fetchLatestRelease(ctx context.Context, cfg *config.Config) (*LatestRelease, error) {
	ctx, cancel := context.WithTimeout(ctx, releaseRPCTimeout)
	defer cancel()

	params := map[string]interface{}{
		"p_platform": runtime.GOOS,
		"p_arch":     runtime.GOARCH,
	}
	var rows []LatestRelease
	err := withAuthRetry(ctx, cfg, func() error {
		rows = nil
		return supabase.FromConfig(cfg).RPC(ctx, "get_latest_agent_release", params, &rows)
	})
	if err != nil {
		return nil, fmt.Errorf("get_latest_agent_release RPC: %w", err)
	}
	if len(rows) == 0 {
		return nil, nil
	}
	return &rows[0], nil
}

// CheckInternetConnectivity checks if the network is up by TCP-dialing the
// Supabase host first, then falling back to well-known public endpoints.
func CheckInternetConnectivity(supabaseURL string) bool {
	endpoints := []string{
		"google.com:443",
		"cloudflare.com:443",
	}

	// Prefer checking the Supabase host directly.
	if u, err := url.Parse(supabaseURL); err == nil && u.Host != "" {
		host := u.Hostname()
		endpoints = append([]string{host + ":443"}, endpoints...)
	}

	for _, endpoint := range endpoints {
		conn, err := dialTimeout("tcp", endpoint, 5*time.Second)
		if err == nil {
			if closeErr := conn.Close(); closeErr != nil {
				log.Printf("Error closing connection to %s: %v", endpoint, closeErr)
			}
			log.Printf("Internet connectivity confirmed via %s", endpoint)
			return true
		}
	}

	log.Printf("No internet connectivity detected")
	return false
}

// CheckInternetWithHTTP verifies connectivity by issuing a GET to the Supabase
// REST endpoint.
func CheckInternetWithHTTP(supabaseURL string) bool {
	resp, err := connectivityClient.Get(supabaseURL + "/rest/v1/")
	if err != nil {
		log.Printf("HTTP connectivity check failed: %v", err)
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	// Any HTTP response (even 401/404) means the host is reachable.
	if resp.StatusCode >= http.StatusOK {
		log.Printf("HTTP connectivity confirmed to Supabase (%d)", resp.StatusCode)
		return true
	}
	return false
}

// StartupUpdateCheck checks connectivity then attempts an update if connected.
func StartupUpdateCheck(ctx context.Context, cfg *config.Config) error {
	log.Println("Performing startup update check...")

	if !CheckInternetConnectivity(cfg.SupabaseURL) {
		log.Println("No internet connection on startup, skipping update check")
		return nil
	}

	if !CheckInternetWithHTTP(cfg.SupabaseURL) {
		log.Println("HTTP connectivity check failed on startup, skipping update check")
		return nil
	}

	log.Println("Internet connection confirmed, checking for updates...")

	if err := CheckAndApplyWithRetry(ctx, cfg); err != nil {
		log.Printf("Startup update check failed: %v", err)
		return fmt.Errorf("startup update check failed: %w", err)
	}

	log.Println("Startup update check completed successfully")
	return nil
}
