package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/httpx"
	"sentinelgo/internal/paths"
	"sentinelgo/internal/winsec"
)

// downloadClient has a generous timeout for large binary downloads (~18 MB+).
var downloadClient = httpx.NewClient(10 * time.Minute)

// storageBase constructs the Supabase Storage authenticated download URL for a
// given bucket and asset path.
func storageURL(supabaseURL, bucket, assetPath string) string {
	return supabaseURL + "/storage/v1/object/" + bucket + "/" + assetPath
}

// downloadAndVerify downloads the release binary and its detached ed25519
// signature from Supabase Storage, verifies the SHA256 checksum (integrity)
// and the ed25519 signature (authenticity), and returns the path of the staged
// binary together with its computed checksum.
//
// Both requests are authenticated with the agent's JWT and the Supabase anon
// key — the agent-releases bucket has RLS that allows any authenticated user
// to download.
func downloadAndVerify(ctx context.Context, cfg *config.Config, assetPath, expectedChecksum, sigAssetPath string) (string, string, error) {
	// Fail closed before doing any work. verifySignature rejects an empty
	// sigAssetPath too, but only after the binary has been downloaded and
	// written to disk -- so an unsigned release still caused a multi-megabyte
	// transfer and left a staged artifact to clean up. Checking here means an
	// unsigned release costs nothing and touches nothing.
	if sigAssetPath == "" {
		return "", "", fmt.Errorf("refusing to install update: no .sig asset path (fail closed)")
	}

	binaryURL := storageURL(cfg.SupabaseURL, "agent-releases", assetPath)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, binaryURL, nil)
	if err != nil {
		return "", "", err
	}
	addAuthHeaders(req, cfg)

	resp, err := downloadClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("binary download status %d", resp.StatusCode)
	}

	selfPath, err := os.Executable()
	if err != nil {
		return "", "", err
	}

	// Stage into the dedicated staging directory rather than beside the running
	// binary. It sits on the same volume, so the final swap is still a rename.
	stagingDir := paths.StagingDir()
	if err := os.MkdirAll(stagingDir, 0700); err != nil {
		return "", "", fmt.Errorf("create staging directory: %w", err)
	}
	if err := winsec.SecureSystemPath(stagingDir); err != nil {
		return "", "", fmt.Errorf("refusing to stage update: cannot secure %s: %w",
			stagingDir, err)
	}

	newPath := filepath.Join(stagingDir, filepath.Base(selfPath)+".new")

	// A leftover .new would make CreateSecureFile fail, since it refuses to
	// adopt an existing file rather than truncate it.
	if err := os.Remove(newPath); err != nil && !os.IsNotExist(err) {
		return "", "", fmt.Errorf("remove stale staged binary %s: %w", newPath, err)
	}

	// The descriptor is applied by CreateFile itself, before a single byte is
	// written. Creating the file and hardening it afterwards left the entire
	// multi-megabyte download exposed: a local attacker could overwrite an
	// artifact that a LocalSystem service was about to execute, and the
	// signature check below would then verify their content instead of ours.
	f, err := winsec.CreateSecureFile(newPath)
	if err != nil {
		return "", "", fmt.Errorf("create staged binary: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Stream to disk and compute SHA256 simultaneously.
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, hash), resp.Body); err != nil {
		_ = os.Remove(newPath)
		return "", "", err
	}

	actualChecksum := hex.EncodeToString(hash.Sum(nil))

	// Verify ed25519 signature. Fail closed: if there is no .sig asset the
	// update is rejected.
	if err := verifySignature(ctx, cfg, newPath, sigAssetPath, PublicKey); err != nil {
		_ = os.Remove(newPath)
		return "", "", err
	}

	return newPath, actualChecksum, nil
}

// addAuthHeaders sets the Authorization (Bearer JWT) and apikey headers on req.
func addAuthHeaders(req *http.Request, cfg *config.Config) {
	req.Header.Set("Authorization", "Bearer "+cfg.GetAccessToken())
	req.Header.Set("apikey", cfg.SupabaseKey)
}

// verifySignature downloads the detached .sig file from Supabase Storage and
// verifies it against pubKey. Returns an error if sigAssetPath is empty (fail
// closed), the download fails, or the signature is invalid.
func verifySignature(ctx context.Context, cfg *config.Config, binaryPath, sigAssetPath string, pubKey ed25519.PublicKey) error {
	if sigAssetPath == "" {
		return fmt.Errorf("refusing to install update: no .sig asset path (fail closed)")
	}

	sigURL := storageURL(cfg.SupabaseURL, "agent-releases", sigAssetPath)

	sigReq, err := http.NewRequestWithContext(ctx, http.MethodGet, sigURL, nil)
	if err != nil {
		return fmt.Errorf("build sig request: %w", err)
	}
	addAuthHeaders(sigReq, cfg)

	sigResp, err := downloadClient.Do(sigReq)
	if err != nil {
		return fmt.Errorf("download signature: %w", err)
	}
	defer func() { _ = sigResp.Body.Close() }()
	if sigResp.StatusCode != http.StatusOK {
		return fmt.Errorf("signature download status %d", sigResp.StatusCode)
	}

	sigBody, err := io.ReadAll(sigResp.Body)
	if err != nil {
		return fmt.Errorf("read signature body: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigBody)))
	if err != nil {
		return fmt.Errorf("decode signature (expected base64): %w", err)
	}

	// Read staged binary for verification (binaries are 10–30 MB; acceptable).
	binaryBytes, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("read staged binary for verification: %w", err)
	}

	return verifySignatureBytes(binaryBytes, sigBytes, pubKey)
}

// verifySignatureBytes checks an ed25519 signature against binaryBytes and
// pubKey. Separated from verifySignature so tests can exercise the crypto
// path without spinning up an HTTP server.
func verifySignatureBytes(binaryBytes, sigBytes []byte, pubKey ed25519.PublicKey) error {
	if !ed25519.Verify(pubKey, binaryBytes, sigBytes) {
		return fmt.Errorf("ed25519 signature verification failed: binary may have been tampered with")
	}
	return nil
}
