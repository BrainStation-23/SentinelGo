// Package hashutil provides a platform-neutral SHA-256 file hashing primitive.
// It lives here — rather than in internal/epm — so that both internal/epm and
// internal/service/software can import it without creating an import cycle.
package hashutil

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// ComputeFileHash returns the lowercase hex-encoded SHA-256 digest of the file
// at path. The caller receives a non-nil error when the file cannot be opened
// or read; in that case the returned string is empty.
func ComputeFileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open file for hashing: %w", err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash file: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}
