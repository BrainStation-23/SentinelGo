package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/httpx"
	"sentinelgo/internal/sanitize"
)

// GitHubRelease represents a GitHub release response
type GitHubRelease struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

// Asset represents a GitHub release asset
type Asset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

var updateMutex sync.Mutex

// windowsServiceName is the SCM service name registered at install time
// (see cmd/sentinelgo/main.go). The Windows update path restarts via SCM
// because a running .exe cannot be replaced in place.
const windowsServiceName = "SentinelGo"

// HTTP clients with finite timeouts. http.DefaultClient has no timeout, so a
// hung connection during a release check or download would block the update
// path forever while holding updateMutex.
var (
	apiClient      = httpx.NewClient(30 * time.Second)
	downloadClient = httpx.NewClient(10 * time.Minute)
)

// CheckAndApply checks for a newer release and applies the update if available.
//
// Order of operations is deliberate (see the audit fixes for C3/C4 and M2):
//  1. Compare against the COMPILED-IN running version (config.Version), not the
//     persisted cfg.CurrentVersion. The running binary's version is the source
//     of truth, so a failed swap can never leave the agent reporting a version
//     it isn't actually running.
//  2. Only update on a strictly-newer semantic version (blocks downgrades).
//  3. Require a SHA256 checksum and a trusted HTTPS GitHub URL.
//  4. Download and verify BEFORE replacing anything; abort cleanly on any
//     failure so monitoring capacity is never lost to a failed update.
//  5. Replace + restart via the OS service manager. The version is NOT
//     persisted here — the restarted new binary asserts its own version on
//     startup (config.Load), so a failed update is retried on the next check.
func CheckAndApply(ctx context.Context, cfg *config.Config, token string) error {
	updateMutex.Lock()
	defer updateMutex.Unlock()

	latest, err := fetchLatestRelease(ctx, cfg, token)
	if err != nil {
		return fmt.Errorf("fetch latest release: %w", err)
	}

	running := config.Version
	newer, err := isNewerVersion(latest.TagName, running)
	if err != nil {
		// Cannot compare versions (e.g. a "dev" build). Skip rather than risk
		// applying an unverifiable or wrong-direction change.
		fmt.Printf("Skipping update: cannot compare versions (%v)\n", err)
		return nil
	}
	if !newer {
		fmt.Printf("Already up to date (running %s, latest %s)\n",
			sanitize.ForLog(running), sanitize.ForLog(latest.TagName))
		return nil
	}

	assetURL, expectedChecksum, err := selectAssetWithChecksum(latest, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return fmt.Errorf("select asset: %w", err)
	}

	// M2: only download from a trusted HTTPS GitHub host.
	if err := validateGitHubURL(assetURL); err != nil {
		return fmt.Errorf("refusing to download release asset: %w", err)
	}

	// M2: a checksum is mandatory. This is a corruption guard, not authenticity
	// (cryptographic signature verification is a deferred follow-up). Fail closed
	// rather than installing an unverifiable binary.
	if expectedChecksum == "" {
		return fmt.Errorf("refusing to update to %s: no SHA256 checksum published with the release",
			sanitize.ForLog(latest.TagName))
	}

	fmt.Printf("Found update: %s -> %s\n", sanitize.ForLog(running), sanitize.ForLog(latest.TagName))

	// A backup is mandatory so a failed in-place replace can always roll back.
	backupPath, err := createBackup()
	if err != nil {
		return fmt.Errorf("refusing to update without a backup: %w", err)
	}
	fmt.Printf("Created backup: %s\n", backupPath)

	// Download and verify BEFORE touching the running install. If anything fails
	// here, the running agent is untouched.
	newPath, actualChecksum, err := downloadAndVerify(ctx, assetURL, expectedChecksum, latest.TagName)
	if err != nil {
		_ = removeFile(backupPath)
		return fmt.Errorf("download and verify failed: %w", err)
	}
	if actualChecksum != expectedChecksum {
		_ = os.Remove(newPath)
		_ = removeFile(backupPath)
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
	}

	// Replace the binary. On Unix this is an atomic in-place rename now; on
	// Windows the running .exe cannot be replaced, so the swap is deferred to a
	// post-exit script in restart().
	if runtime.GOOS != "windows" {
		if err := atomicReplace(newPath); err != nil {
			if rbErr := rollbackFromBackup(backupPath); rbErr != nil {
				return fmt.Errorf("atomic replace failed (%v) and rollback failed: %w", err, rbErr)
			}
			_ = removeFile(backupPath)
			return fmt.Errorf("atomic replace failed, rolled back to previous version: %w", err)
		}
	}

	fmt.Printf("Update verified and staged: %s -> %s\n", running, latest.TagName)
	_ = removeFile(backupPath)

	// Hand off to the service manager. Does not persist CurrentVersion — see the
	// function doc; the restarted binary reconciles its own version on startup.
	return restart(newPath)
}

// CheckAndApplyWithRetry performs an update check and apply with up to 3 retry attempts.
func CheckAndApplyWithRetry(ctx context.Context, cfg *config.Config, token string) error {
	const maxAttempts = 3
	var lastErr error

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(attempt) * time.Second):
				log.Printf("Update attempt %d/%d after backoff", attempt+1, maxAttempts)
			}
		}

		err := CheckAndApply(ctx, cfg, token)
		if err == nil {
			return nil
		}

		lastErr = err
		log.Printf("Update attempt %d/%d failed: %v", attempt+1, maxAttempts, err)
	}

	return fmt.Errorf("update failed after %d attempts: %w", maxAttempts, lastErr)
}

func fetchLatestRelease(ctx context.Context, cfg *config.Config, token string) (*GitHubRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", cfg.GitHubOwner, cfg.GitHubRepo)
	sanitizedUrl := sanitize.ForLog(url)
	fmt.Printf("Fetching release from: %s\n", sanitizedUrl)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := apiClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API status %d", resp.StatusCode)
	}

	var rel GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, err
	}

	fmt.Printf("Fetched release: %s with %d assets\n", rel.TagName, len(rel.Assets))
	return &rel, nil
}

func selectAssetWithChecksum(rel *GitHubRelease, goos, goarch string) (string, string, error) {
	var suffix string
	switch goos {
	case "windows":
		suffix = ".exe"
	case "linux", "darwin":
		suffix = ""
	default:
		return "", "", fmt.Errorf("unsupported OS %s", goos)
	}

	pattern := fmt.Sprintf("sentinelgo-%s-%s%s", goos, goarch, suffix)
	fmt.Printf("Looking for asset: %s\n", pattern)
	fmt.Printf("Available assets: %v\n", func() (names []string) {
		for _, asset := range rel.Assets {
			names = append(names, asset.Name)
		}
		return
	}())

	for _, asset := range rel.Assets {
		if asset.Name == pattern {
			fmt.Printf("Found matching asset: %s\n", asset.Name)
			return asset.URL, extractChecksumFromAsset(asset), nil
		}
	}
	return "", "", fmt.Errorf("no matching asset for %s-%s", goos, goarch)
}

// extractChecksumFromAsset extracts SHA256 checksum from asset information.
func extractChecksumFromAsset(asset Asset) string {
	if strings.HasSuffix(asset.Name, "SHA256SUMS") || strings.HasSuffix(asset.Name, "sha256sums") {
		return downloadAndParseChecksumFile(asset.URL)
	}

	if idx := strings.Index(asset.Name, "sha256:"); idx != -1 {
		checksum := strings.TrimRight(asset.Name[idx+7:], " )\n\r")
		if len(checksum) == 64 {
			return checksum
		}
	}

	return ""
}

// downloadAndParseChecksumFile downloads a SHA256SUMS file and returns the checksum
// for the current platform's binary.
func downloadAndParseChecksumFile(url string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return ""
	}

	resp, err := apiClient.Do(req)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	pattern := fmt.Sprintf("sentinelgo-%s-%s", runtime.GOOS, runtime.GOARCH)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, pattern) {
			parts := strings.Fields(line)
			if len(parts) >= 1 {
				return parts[0]
			}
		}
	}

	return ""
}

// CheckInternetConnectivity checks if internet connection is available via TCP dial.
func CheckInternetConnectivity() bool {
	endpoints := []string{
		"api.github.com:443",
		"google.com:443",
		"cloudflare.com:443",
	}

	for _, endpoint := range endpoints {
		conn, err := net.DialTimeout("tcp", endpoint, 5*time.Second)
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

// CheckInternetWithHTTP checks internet connectivity via HTTP request to GitHub.
func CheckInternetWithHTTP() bool {
	client := httpx.NewClient(10 * time.Second)

	resp, err := client.Get("https://api.github.com")
	if err != nil {
		log.Printf("HTTP connectivity check failed: %v", err)
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK {
		log.Printf("HTTP connectivity confirmed to GitHub API")
		return true
	}

	return false
}

// StartupUpdateCheck checks internet connectivity then attempts an update if connected.
func StartupUpdateCheck(ctx context.Context, cfg *config.Config, token string) error {
	log.Println("Performing startup update check...")

	if !CheckInternetConnectivity() {
		log.Println("No internet connection on startup, skipping update check")
		return nil
	}

	if !CheckInternetWithHTTP() {
		log.Println("HTTP connectivity check failed on startup, skipping update check")
		return nil
	}

	log.Println("Internet connection confirmed, checking for updates...")

	if err := CheckAndApplyWithRetry(ctx, cfg, token); err != nil {
		log.Printf("Startup update check failed: %v", err)
		return fmt.Errorf("startup update check failed: %w", err)
	}

	log.Println("Startup update check completed successfully")
	return nil
}

// AutoUpdateChecker runs automatic update checks in the background every hour.
func AutoUpdateChecker(ctx context.Context, cfg *config.Config) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			log.Println("Checking for updates...")

			if err := CheckAndApplyWithRetry(ctx, cfg, ""); err != nil {
				log.Printf("Auto-update failed: %v\n", err)
			} else {
				log.Println("Auto-update completed successfully")
			}
		}
	}
}
