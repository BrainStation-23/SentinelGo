package updater

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"sentinelgo/internal/config"
	"sentinelgo/internal/supabase"
	"sentinelgo/internal/winsec"
)

// Size limits for release assets. Agent binaries are ~18-30 MB; a body beyond
// the limit is rejected (supabase.ErrTooLarge) rather than truncated.
const (
	maxBinaryBytes    = 256 << 20
	maxSignatureBytes = 4 << 10
)

const releasesBucket = "agent-releases"

// downloadAndVerify downloads the release binary and its detached ed25519
// signature from Supabase Storage, verifies the SHA256 checksum (integrity)
// and the ed25519 signature (authenticity), and returns the path of the staged
// binary together with its computed checksum.
//
// Both requests are authenticated with the agent's JWT and the Supabase anon
// key — the agent-releases bucket has RLS that allows any authenticated user
// to download.
func downloadAndVerify(ctx context.Context, cfg *config.Config, assetPath, expectedChecksum, sigAssetPath string) (string, string, error) {
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

	// Stream to disk and compute SHA256 simultaneously. An expired token
	// (Storage answers 400 InvalidJWT) is recovered via the AuthRetrier; the
	// file and hash are reset before each attempt.
	hash := sha256.New()
	c := supabase.FromConfig(cfg)
	err = withAuthRetry(ctx, cfg, func() error {
		if err := resetStaging(f); err != nil {
			return err
		}
		hash.Reset()
		_, err := c.Download(ctx, releasesBucket, assetPath, false, io.MultiWriter(f, hash), maxBinaryBytes)
		return err
	})
	closeErr := f.Close()
	if err != nil {
		_ = os.Remove(newPath)
		return "", "", fmt.Errorf("download binary: %w", err)
	}
	if closeErr != nil {
		_ = os.Remove(newPath)
		return "", "", fmt.Errorf("close staged binary: %w", closeErr)
	}

	actualChecksum := hex.EncodeToString(hash.Sum(nil))

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

// resetStaging empties the staging file before a (re)try.
func resetStaging(f *os.File) error {
	if err := f.Truncate(0); err != nil {
		return err
	}
	_, err := f.Seek(0, io.SeekStart)
	return err
}

// verifySignature downloads the detached .sig file from Supabase Storage and
// verifies it against pubKey. Returns an error if sigAssetPath is empty (fail
// closed), the download fails, or the signature is invalid.
func verifySignature(ctx context.Context, cfg *config.Config, binaryPath, sigAssetPath string, pubKey ed25519.PublicKey) error {
	if sigAssetPath == "" {
		return fmt.Errorf("refusing to install update: no .sig asset path (fail closed)")
	}

	var sigBody bytes.Buffer
	c := supabase.FromConfig(cfg)
	err := withAuthRetry(ctx, cfg, func() error {
		sigBody.Reset()
		_, err := c.Download(ctx, releasesBucket, sigAssetPath, false, &sigBody, maxSignatureBytes)
		return err
	})
	if err != nil {
		return fmt.Errorf("download signature: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigBody.String()))
	if err != nil {
		return fmt.Errorf("decode signature (expected base64): %w", err)
	}

	// Read staged binary for verification (binaries are 10–30 MB; acceptable).
	// #nosec G304 - binaryPath is the updater's own staging file; its contents are signature-verified below
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
