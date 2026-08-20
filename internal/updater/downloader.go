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
	"strings"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/httpx"
	"sentinelgo/internal/winsec"
)

// downloadClient has a generous timeout for large binary downloads (~18 MB+).
var downloadClient = httpx.NewClient(10 * time.Minute)

const maxReleaseBytes int64 = 256 * 1024 * 1024

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
func downloadAndVerify(ctx context.Context, cfg *config.Config, assetPath, expectedChecksum, sigAssetPath string, expectedSize int64) (string, string, error) {
	if expectedSize <= 0 || expectedSize > maxReleaseBytes {
		return "", "", fmt.Errorf("invalid release size %d (max %d)", expectedSize, maxReleaseBytes)
	}
	if len(expectedChecksum) != sha256.Size*2 {
		return "", "", fmt.Errorf("invalid SHA256 in release manifest")
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
	if resp.ContentLength > expectedSize || resp.ContentLength > maxReleaseBytes {
		return "", "", fmt.Errorf("binary response size %d exceeds manifest size %d", resp.ContentLength, expectedSize)
	}

	selfPath, err := os.Executable()
	if err != nil {
		return "", "", err
	}

	newPath := selfPath + ".new"
	// #nosec G302,G304 - New binary needs executable permissions, path is controlled
	f, err := os.OpenFile(newPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = f.Close() }()

	// Stream to disk and compute SHA256 simultaneously.
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(f, hash), io.LimitReader(resp.Body, expectedSize+1))
	if err != nil {
		_ = os.Remove(newPath)
		return "", "", err
	}
	if written != expectedSize {
		_ = os.Remove(newPath)
		return "", "", fmt.Errorf("binary size mismatch: manifest %d, downloaded %d", expectedSize, written)
	}

	actualChecksum := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(actualChecksum, expectedChecksum) {
		_ = os.Remove(newPath)
		return "", actualChecksum, fmt.Errorf("checksum mismatch")
	}

	// Lock the staged binary down so a standard user cannot swap it between
	// download and the privileged replace/restart.
	if err := winsec.SecurePath(newPath); err != nil {
		fmt.Printf("Warning: failed to secure staged binary ACL: %v\n", err)
	}

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
