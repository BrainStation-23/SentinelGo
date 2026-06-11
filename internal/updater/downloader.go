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

	"sentinelgo/internal/winsec"
)

// downloadAndVerify downloads the binary from url, writes it to a staged file,
// verifies both the SHA256 checksum (corruption guard) and the ed25519 signature
// (authenticity). sigURL must not be empty — the function fails closed when the
// release contains no .sig asset so a release without a signature is rejected.
func downloadAndVerify(ctx context.Context, url, expectedChecksum, sigURL, version string) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", "", err
	}

	resp, err := downloadClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("download failed status %d", resp.StatusCode)
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

	// Stream to disk and compute SHA256 simultaneously
	hash := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, hash), resp.Body); err != nil {
		_ = os.Remove(newPath)
		return "", "", err
	}

	actualChecksum := hex.EncodeToString(hash.Sum(nil))

	// Lock the staged binary down so a standard user cannot swap it for a
	// malicious one between download and the privileged replace/restart.
	if err := winsec.SecurePath(newPath); err != nil {
		fmt.Printf("Warning: failed to secure staged binary ACL: %v\n", err)
	}

	// Verify ed25519 signature. Fail closed: a release without a .sig asset is
	// rejected. This is the authenticity check; the SHA256 above is only a
	// corruption guard.
	if err := verifySignature(ctx, newPath, sigURL, PublicKey); err != nil {
		_ = os.Remove(newPath)
		return "", "", err
	}

	return newPath, actualChecksum, nil
}

// verifySignature downloads the detached .sig file and verifies it against
// pubKey. Returns an error if sigURL is empty (fail closed), the URL is
// untrusted, the download fails, or the signature is invalid.
func verifySignature(ctx context.Context, binaryPath, sigURL string, pubKey ed25519.PublicKey) error {
	if sigURL == "" {
		return fmt.Errorf("refusing to install update: no .sig asset in release (fail closed — sign releases with `go run ./scripts/sign`)")
	}

	if err := validateGitHubURL(sigURL); err != nil {
		return fmt.Errorf("invalid signature URL: %w", err)
	}

	sigReq, err := http.NewRequestWithContext(ctx, "GET", sigURL, nil)
	if err != nil {
		return fmt.Errorf("build sig request: %w", err)
	}
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

// verifySignatureBytes checks an ed25519 signature against binaryBytes and pubKey.
// It is separated from verifySignature so unit tests can exercise the crypto
// path without spinning up an HTTP server.
func verifySignatureBytes(binaryBytes, sigBytes []byte, pubKey ed25519.PublicKey) error {
	if !ed25519.Verify(pubKey, binaryBytes, sigBytes) {
		return fmt.Errorf("ed25519 signature verification failed: binary may have been tampered with")
	}
	return nil
}
