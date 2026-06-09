package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
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

// ProcessInfo contains information about a running SentinelGo process
type ProcessInfo struct {
	PID     int
	Version string
	CmdLine string
}

var updateMutex sync.Mutex

// CheckAndApply checks for a newer release and applies the update if available.
func CheckAndApply(ctx context.Context, cfg *config.Config, token string) error {
	updateMutex.Lock()
	defer updateMutex.Unlock()

	latest, err := fetchLatestRelease(ctx, cfg, token)
	if err != nil {
		return fmt.Errorf("fetch latest release: %w", err)
	}

	if latest.TagName == cfg.CurrentVersion {
		fmt.Printf("Already up to date: %s\n", latest.TagName)
		// Still update config to ensure it reflects current version
		cfg.CurrentVersion = latest.TagName
		if err := cfg.SaveAtomic(); err != nil {
			return fmt.Errorf("save config: %w", err)
		}
		return nil
	}

	assetURL, expectedChecksum, err := selectAssetWithChecksum(latest, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		return fmt.Errorf("select asset: %w", err)
	}

	// NOTE: expectedChecksum may be empty if the release does not include a SHA256SUMS
	// file or embed checksums in asset names. In that case, verification is skipped with
	// a warning. Future work: require a checksum by publishing SHA256SUMS with each release.

	sanitizedCurrentVersion := sanitize.ForLog(cfg.CurrentVersion)
	sanitizedTagName := sanitize.ForLog(latest.TagName)
	fmt.Printf("Found update: %s -> %s\n", sanitizedCurrentVersion, sanitizedTagName)

	backupPath, err := createBackup()
	if err != nil {
		fmt.Printf("Warning: Failed to create backup: %v\n", err)
	} else {
		fmt.Printf("Created backup: %s\n", backupPath)
	}

	fmt.Println("Stopping old SentinelGo processes before update...")
	if err := stopOldProcesses(); err != nil {
		fmt.Printf("Warning: Failed to stop some old processes: %v\n", err)
	}

	fmt.Println("Waiting for old processes to fully terminate...")
	time.Sleep(5 * time.Second)

	processes, _ := findOldProcesses()
	if len(processes) > 0 {
		fmt.Printf("Warning: %d old process(es) still running, force killing...\n", len(processes))
		for _, proc := range processes {
			fmt.Printf("  PID: %d, Version: %s\n", proc.PID, proc.Version)
		}
		forceKillProcesses(processes)
		time.Sleep(2 * time.Second)
	} else {
		fmt.Println("All old processes stopped successfully")
	}

	newPath, actualChecksum, err := downloadAndVerify(ctx, assetURL, expectedChecksum, latest.TagName)
	if err != nil {
		if backupPath != "" {
			fmt.Printf("Update failed, attempting rollback from backup: %s\n", backupPath)
			if rollbackErr := rollbackFromBackup(backupPath); rollbackErr != nil {
				return fmt.Errorf("update failed and rollback failed: %v, rollback error: %w", err, rollbackErr)
			}
			fmt.Println("Successfully rolled back to previous version")
		}
		return fmt.Errorf("download and verify failed: %w", err)
	}

	if expectedChecksum != "" && actualChecksum != expectedChecksum {
		if backupPath != "" {
			fmt.Printf("Checksum mismatch, attempting rollback from backup: %s\n", backupPath)
			if rollbackErr := rollbackFromBackup(backupPath); rollbackErr != nil {
				return fmt.Errorf("checksum mismatch and rollback failed; rollback error: %w", rollbackErr)
			}
			fmt.Println("Successfully rolled back to previous version due to checksum mismatch")
		}
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
	}

	if expectedChecksum == "" {
		fmt.Printf("Warning: No checksum provided in release, skipping verification. Downloaded checksum: %s\n", actualChecksum)
	}

	if runtime.GOOS != "windows" {
		if err := atomicReplace(newPath); err != nil {
			if backupPath != "" {
				fmt.Printf("Atomic replacement failed, attempting rollback from backup: %s\n", backupPath)
				if rollbackErr := rollbackFromBackup(backupPath); rollbackErr != nil {
					return fmt.Errorf("atomic replacement failed and rollback failed: %w, rollback error: %w", err, rollbackErr)
				}
				fmt.Println("Successfully rolled back to previous version")
			}
			return fmt.Errorf("atomic replacement failed: %w", err)
		}
	} else {
		fmt.Println("Windows update will replace binary after restart")
	}

	fmt.Printf("Successfully updated to version %s\n", latest.TagName)

	cfg.CurrentVersion = latest.TagName
	if err := cfg.SaveAtomic(); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	if backupPath != "" {
		_ = removeFile(backupPath)
	}

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

	resp, err := http.DefaultClient.Do(req)
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

	resp, err := http.DefaultClient.Do(req)
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
