// Package artifact handles verified streaming downloads of task artifacts from
// Supabase Storage. Each artifact is validated against a contract spec, then
// fetched with hash-while-streaming and exact size enforcement — the script
// never runs if any check fails.
//
// The package is intentionally narrow in scope: it only adds; the updater
// (internal/updater) can adopt it later, but that would trigger the self-update
// staging gate and is a separate decision.
package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"sentinelgo/internal/supabase"
)

// AuthRetrier recovers the session on a 401 and retries once. It is satisfied
// by a thin wrapper around *auth.Service; kept as a local interface so this
// package does not import the auth or config packages.
type AuthRetrier interface {
	// RefreshToken refreshes the access token using the stored credentials.
	// It is called once when a 401 is received; the caller then retries.
	RefreshToken(ctx context.Context) error
}

// Spec describes a single task artifact (contract §1).
type Spec struct {
	ID       string `json:"id"`
	Bucket   string `json:"bucket"`
	Path     string `json:"path"`
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}

// maxArtifactSize is the maximum allowed size per artifact (4 GiB, contract §1).
const maxArtifactSize = 4 << 30

// maxArtifacts is the maximum number of artifacts per task (contract §1).
const maxArtifacts = 5

// allowedBuckets is the v1 bucket allowlist (contract §1).
var allowedBuckets = map[string]bool{
	"app-installers": true,
}

// idRe is the allowlist for artifact IDs (contract §1): ^[a-z][a-z0-9_]{0,31}$
var idRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// filenameRe is the allowlist for artifact filenames (contract §1).
var filenameRe = regexp.MustCompile(`^[A-Za-z0-9._ \-]{1,128}$`)

// sha256Re validates that a sha256 value is exactly 64 lowercase hex chars.
var sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Validate checks every spec against contract §1 rules.
// Errors are returned as a combined error listing all violations.
func Validate(specs []Spec) error {
	if len(specs) > maxArtifacts {
		return fmt.Errorf("too many artifacts: %d (max %d)", len(specs), maxArtifacts)
	}

	seen := make(map[string]bool, len(specs))
	var errs []string

	for i, s := range specs {
		prefix := fmt.Sprintf("artifact[%d] (id=%q)", i, s.ID)

		if !idRe.MatchString(s.ID) {
			errs = append(errs, fmt.Sprintf("%s: id must match ^[a-z][a-z0-9_]{0,31}$", prefix))
		}
		if seen[s.ID] {
			errs = append(errs, fmt.Sprintf("%s: duplicate id", prefix))
		}
		seen[s.ID] = true

		if !allowedBuckets[s.Bucket] {
			errs = append(errs, fmt.Sprintf("%s: bucket %q is not in the v1 allowlist", prefix, s.Bucket))
		}

		if s.Path == "" || s.Path[0] == '/' {
			errs = append(errs, fmt.Sprintf("%s: path must not be empty or start with '/'", prefix))
		}
		if containsPathTraversal(s.Path) {
			errs = append(errs, fmt.Sprintf("%s: path must not contain '..' segment", prefix))
		}

		if !filenameRe.MatchString(s.Filename) {
			errs = append(errs, fmt.Sprintf("%s: filename must match ^[A-Za-z0-9._ -]{1,128}$", prefix))
		}
		if s.Filename == "." || s.Filename == ".." {
			errs = append(errs, fmt.Sprintf("%s: filename must not be '.' or '..'", prefix))
		}

		if !sha256Re.MatchString(s.SHA256) {
			errs = append(errs, fmt.Sprintf("%s: sha256 must be 64 lowercase hex characters", prefix))
		}

		if s.Size < 1 {
			errs = append(errs, fmt.Sprintf("%s: size must be at least 1", prefix))
		} else if s.Size > maxArtifactSize {
			errs = append(errs, fmt.Sprintf("%s: size %d exceeds max %d bytes (4 GiB)", prefix, s.Size, maxArtifactSize))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("artifact validation failed:\n  %s",
			joinStrings(errs, "\n  "))
	}
	return nil
}

// containsPathTraversal reports whether path contains a ".." segment.
func containsPathTraversal(path string) bool {
	// Normalise to forward slashes and split on them.
	normalized := filepath.ToSlash(path)
	for _, seg := range splitSlash(normalized) {
		if seg == ".." {
			return true
		}
	}
	return false
}

func splitSlash(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '/' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func joinStrings(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	result := ss[0]
	for _, s := range ss[1:] {
		result += sep + s
	}
	return result
}

// retryableStatusCodes are HTTP statuses that warrant a retry (transient errors).
var retryableStatusCodes = map[int]bool{
	408: true, // Request Timeout
	429: true, // Too Many Requests
	500: true,
	502: true,
	503: true,
	504: true,
}

// maxRetries is the number of additional attempts after the first failure.
const maxRetries = 2

// retryBaseDelay is the base delay for exponential backoff between retries.
// A var (not const) so tests can override it without sleeping.
var retryBaseDelay = time.Second

// Fetch downloads every spec into dir/<Filename> in order and returns the
// absolute paths keyed by artifact ID.
//
// It fails (and removes partial files) on any size/hash mismatch. The overall
// bound is the task context; the caller sizes timeout_minutes to fit.
//
// retry may be nil; in that case 401 errors are not recovered.
func Fetch(ctx context.Context, c *supabase.Client, retry AuthRetrier, dir string, specs []Spec) (map[string]string, error) {
	// Check free disk space before any download.
	if err := checkDiskSpace(dir, specs); err != nil {
		return nil, err
	}

	paths := make(map[string]string, len(specs))

	for _, spec := range specs {
		destPath := filepath.Join(dir, spec.Filename)
		absPath, err := downloadArtifact(ctx, c, retry, destPath, spec)
		if err != nil {
			// Clean up any files already downloaded in this call.
			for _, p := range paths {
				_ = os.Remove(p)
			}
			return nil, fmt.Errorf("artifact %q: %w", spec.ID, err)
		}
		paths[spec.ID] = absPath
		log.Printf("Artifact: downloaded %s (%s, %d bytes, sha256: %s...)", spec.ID, spec.Filename, spec.Size, spec.SHA256[:12])
	}

	return paths, nil
}

// downloadArtifact downloads a single artifact to destPath with retries,
// 401 recovery, and size+hash verification.
func downloadArtifact(ctx context.Context, c *supabase.Client, retry AuthRetrier, destPath string, spec Spec) (string, error) {
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Backoff: 1s, 2s
			wait := retryBaseDelay * time.Duration(attempt)
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(wait):
			}
		}

		err := trySingleDownload(ctx, c, destPath, spec)
		if err == nil {
			abs, absErr := filepath.Abs(destPath)
			if absErr != nil {
				abs = destPath
			}
			return abs, nil
		}

		// 401: recover once via the retrier, then retry immediately (no sleep).
		if supabase.IsUnauthorized(err) {
			if retry == nil {
				return "", fmt.Errorf("unauthorized and no retrier configured: %w", err)
			}
			log.Printf("Artifact: 401 for %s, attempting token refresh", spec.ID)
			if refreshErr := retry.RefreshToken(ctx); refreshErr != nil {
				return "", fmt.Errorf("token refresh failed: %w", refreshErr)
			}
			// Single retry after successful token refresh.
			if retryErr := trySingleDownload(ctx, c, destPath, spec); retryErr == nil {
				abs, absErr := filepath.Abs(destPath)
				if absErr != nil {
					abs = destPath
				}
				return abs, nil
			} else {
				_ = os.Remove(destPath)
				return "", fmt.Errorf("download failed after token refresh: %w", retryErr)
			}
		}

		// 403 / 404: don't retry.
		if supabase.IsForbidden(err) || supabase.IsNotFound(err) {
			_ = os.Remove(destPath)
			return "", fmt.Errorf("agent is not allowed to read artifact %q (task older than 7 days, or RLS missing on the server): %w", spec.ID, err)
		}

		// Transient: retry if there are attempts left.
		if !isTransient(err) {
			_ = os.Remove(destPath)
			return "", err
		}

		log.Printf("Artifact: transient error for %s (attempt %d/%d): %v", spec.ID, attempt+1, maxRetries+1, err)
		lastErr = err
		_ = os.Remove(destPath) // truncate before next attempt
	}

	return "", fmt.Errorf("download failed after %d attempts: %w", maxRetries+1, lastErr)
}

// trySingleDownload performs one download attempt: open/truncate the file,
// stream through a multiwriter (file + sha256), then verify size and hash.
func trySingleDownload(ctx context.Context, c *supabase.Client, destPath string, spec Spec) error {
	// #nosec G304 - destPath is constructed from the validated task temp dir and spec.Filename
	f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open dest file: %w", err)
	}

	h := sha256.New()
	// spec.Size+1 so the limitedWriter inside Download reports ErrTooLarge
	// instead of silent truncation when the server sends one extra byte.
	written, dlErr := c.Download(ctx, spec.Bucket, spec.Path, true, io.MultiWriter(f, h), spec.Size+1)

	closeErr := f.Close()
	if dlErr != nil {
		_ = os.Remove(destPath)
		// ErrTooLarge means the server sent more bytes than spec.Size+1 —
		// that's a fatal mismatch, not a transient network error.
		if errors.Is(dlErr, supabase.ErrTooLarge) {
			return &errFatal{fmt.Errorf("size mismatch: server sent more than %d bytes", spec.Size)}
		}
		return dlErr
	}
	if closeErr != nil {
		_ = os.Remove(destPath)
		return fmt.Errorf("close artifact file: %w", closeErr)
	}

	// Exact size check.
	if written != spec.Size {
		_ = os.Remove(destPath)
		return &errFatal{fmt.Errorf("size mismatch: expected %d bytes, got %d", spec.Size, written)}
	}

	// Hash check.
	actualHash := hex.EncodeToString(h.Sum(nil))
	if actualHash != spec.SHA256 {
		_ = os.Remove(destPath)
		return &errFatal{fmt.Errorf("hash mismatch for artifact %q: expected %s, got %s", spec.ID, spec.SHA256, actualHash)}
	}

	// On Windows, apply a SYSTEM+Administrators ACL so a standard user cannot
	// swap the verified file between hash check and execution (contract §3.5).
	if err := securePath(destPath); err != nil {
		log.Printf("Artifact: warning: failed to apply secure ACL to %s: %v", destPath, err)
	}

	return nil
}

// errFatal wraps errors that must not be retried (size/hash mismatch, etc.).
type errFatal struct{ cause error }

func (e *errFatal) Error() string { return e.cause.Error() }
func (e *errFatal) Unwrap() error { return e.cause }

// isTransient reports whether err is a transient HTTP error worth retrying.
// It returns true for specific HTTP status codes and for non-API errors
// (network-level failures), but NOT for errFatal errors or 4xx client errors.
func isTransient(err error) bool {
	if err == nil {
		return false
	}
	var fatal *errFatal
	if errors.As(err, &fatal) {
		return false
	}
	if e, ok := supabase.AsAPIError(err); ok {
		return retryableStatusCodes[e.Status]
	}
	// Non-API errors are assumed to be network-level (connection reset,
	// DNS failure, etc.) and are worth retrying.
	return true
}
