package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"

	"sentinelgo/internal/winsec"
)

// downloadAndVerify downloads the binary from url, writes it to a temp file,
// and returns the file path plus the SHA256 of the downloaded bytes.
// The caller is responsible for validating actualChecksum against expectedChecksum.
func downloadAndVerify(ctx context.Context, url, expectedChecksum, version string) (string, string, error) {
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
		// Non-fatal: log and proceed (checksum is still verified by the caller).
		fmt.Printf("Warning: failed to secure staged binary ACL: %v\n", err)
	}

	return newPath, actualChecksum, nil
}
