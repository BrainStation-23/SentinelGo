// Package artifact downloads the files a task needs before its script runs
// (installer packages, for example) and proves each one is the file the
// backend meant: the exact byte count and SHA-256 come from the task, and a
// file that doesn't match is deleted and never handed to the script.
//
// It is generic: it knows nothing about MSI, PKG or DEB. The task's
// artifact list is "Contract v1" §1 from issue #134.
package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"sentinelgo/internal/supabase"
	"sentinelgo/internal/winsec"
)

// Spec is one entry of a task's artifacts list (contract §1).
type Spec struct {
	ID       string `json:"id"`
	Bucket   string `json:"bucket"`
	Path     string `json:"path"`
	Filename string `json:"filename"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
}

// Contract §1 limits.
const (
	MaxArtifacts = 5
	MaxSize      = 4 << 30
)

// allowedBuckets is the v1 bucket allowlist.
var allowedBuckets = map[string]bool{"app-installers": true}

var (
	idRe       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	filenameRe = regexp.MustCompile(`^[A-Za-z0-9._ -]{1,128}$`)
	sha256Re   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// windowsDeviceNames are names Windows maps to devices whatever the
// extension ("NUL.msi" is the NUL device), so a write there would never land
// in a file the script could run.
var windowsDeviceNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

// Validate checks every contract §1 rule. It also rejects two specs with the
// same filename (case-insensitively, as Windows and macOS compare names),
// since the second download would overwrite the first.
func Validate(specs []Spec) error {
	if len(specs) > MaxArtifacts {
		return fmt.Errorf("task has %d artifacts, at most %d are allowed", len(specs), MaxArtifacts)
	}
	ids := make(map[string]bool, len(specs))
	names := make(map[string]bool, len(specs))
	for i, s := range specs {
		if err := validateSpec(s); err != nil {
			return fmt.Errorf("artifact %d (%q): %w", i, s.ID, err)
		}
		if ids[s.ID] {
			return fmt.Errorf("artifact id %q appears more than once", s.ID)
		}
		ids[s.ID] = true
		lower := strings.ToLower(s.Filename)
		if names[lower] {
			return fmt.Errorf("artifact filename %q appears more than once", s.Filename)
		}
		names[lower] = true
	}
	return nil
}

func validateSpec(s Spec) error {
	if !idRe.MatchString(s.ID) {
		return fmt.Errorf("invalid id")
	}
	if !allowedBuckets[s.Bucket] {
		return fmt.Errorf("bucket %q is not allowed", s.Bucket)
	}
	if err := validatePath(s.Path); err != nil {
		return err
	}
	if err := validateFilename(s.Filename); err != nil {
		return err
	}
	if !sha256Re.MatchString(s.SHA256) {
		return fmt.Errorf("sha256 must be 64 lowercase hex characters")
	}
	if s.Size < 1 || s.Size > MaxSize {
		return fmt.Errorf("size %d is outside 1..%d", s.Size, int64(MaxSize))
	}
	return nil
}

func validatePath(p string) error {
	if p == "" {
		return fmt.Errorf("path is empty")
	}
	if strings.HasPrefix(p, "/") {
		return fmt.Errorf("path must not start with /")
	}
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return fmt.Errorf("path must not contain a .. segment")
		}
	}
	return nil
}

func validateFilename(name string) error {
	if name == "." || name == ".." || !filenameRe.MatchString(name) {
		return fmt.Errorf("invalid filename %q", name)
	}
	base := strings.ToUpper(strings.TrimRight(strings.SplitN(name, ".", 2)[0], " "))
	if windowsDeviceNames[base] {
		return fmt.Errorf("filename %q is a reserved device name on Windows", name)
	}
	return nil
}

// AuthRetrier runs fn and, if it fails with a 401, recovers the session and
// runs it once more. Callers adapt auth.Service.DoWithAuthRetry to it. A nil
// AuthRetrier runs fn once.
type AuthRetrier func(ctx context.Context, fn func() error) error

// Timing knobs; variables so tests can shrink them.
var (
	// idleTimeout aborts a download when no bytes arrive for this long.
	idleTimeout = 2 * time.Minute
	// retryBackoff is the wait before the 2nd and 3rd attempts.
	retryBackoff = []time.Duration{2 * time.Second, 8 * time.Second}
	// maxRetryWait caps a server's Retry-After hint.
	maxRetryWait = 30 * time.Second
)

// maxAttempts bounds the tries per artifact for transient failures.
const maxAttempts = 3

// diskFree reports the bytes available to this process on the volume holding
// dir; a variable so tests can stub it.
var diskFree = freeBytes

// errStalled is the cause set when the idle watchdog aborts a download.
var errStalled = errors.New("download stalled: no data received")

// httpClient has no total timeout: a multi-GB installer can take longer than
// any fixed bound. Headers must arrive within 60 s, the idle watchdog catches
// a stalled body, and the task context bounds the whole thing.
var httpClient = &http.Client{
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	},
}

// HTTPClient returns the client artifact downloads should use. Pass it to
// supabase.WithHTTPClient when building the client handed to Fetch.
func HTTPClient() *http.Client { return httpClient }

// Fetch downloads every spec into dir/<Filename>, in order, and returns the
// absolute paths keyed by spec ID. Every file must match its spec's size and
// SHA-256. On any error, the files this call wrote are removed.
//
// Unix: dir is 0700 and files 0600. Windows: dir gets a SYSTEM +
// Administrators (+ the agent's account) ACL before anything is written, so a
// standard user can't swap a file between verification and execution.
func Fetch(ctx context.Context, c *supabase.Client, retry AuthRetrier, dir string, specs []Spec) (map[string]string, error) {
	if err := Validate(specs); err != nil {
		return nil, err
	}
	if len(specs) == 0 {
		return map[string]string{}, nil
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve artifacts dir: %w", err)
	}
	if err := prepareDir(absDir); err != nil {
		return nil, err
	}
	if err := checkSpace(absDir, specs); err != nil {
		return nil, err
	}

	paths := make(map[string]string, len(specs))
	for _, s := range specs {
		p := filepath.Join(absDir, s.Filename)
		if err := fetchOne(ctx, c, retry, s, p); err != nil {
			for _, done := range paths {
				_ = os.Remove(done)
			}
			return nil, err
		}
		paths[s.ID] = p
	}
	return paths, nil
}

func prepareDir(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create artifacts dir: %w", err)
	}
	// MkdirAll leaves an existing dir's mode alone.
	// #nosec G302 - a directory needs the execute bit to be entered; 0700 is owner-only
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("restrict artifacts dir: %w", err)
	}
	if err := winsec.SecurePath(dir); err != nil {
		return fmt.Errorf("restrict artifacts dir ACL: %w", err)
	}
	return nil
}

// checkSpace requires the sum of all sizes plus 10% to be free (contract §3.3).
func checkSpace(dir string, specs []Spec) error {
	var total uint64
	for _, s := range specs {
		total += uint64(s.Size) // #nosec G115 - Validate bounds Size to 1..4 GiB
	}
	need := total + (total+9)/10
	free, err := diskFree(dir)
	if err != nil {
		return fmt.Errorf("check free disk space: %w", err)
	}
	if free < need {
		return fmt.Errorf("not enough disk space for artifacts: need %d bytes, %d free", need, free)
	}
	return nil
}

// fetchOne downloads one artifact to path, retrying transient failures.
func fetchOne(ctx context.Context, c *supabase.Client, retry AuthRetrier, s Spec, path string) error {
	start := time.Now()
	log.Printf("Artifact: downloading %s (%s, %d bytes, sha256 %s…)", s.ID, s.Filename, s.Size, s.SHA256[:12])

	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			wait := retryBackoff[min(attempt-2, len(retryBackoff)-1)]
			if ra, ok := supabase.RetryAfter(err); ok {
				wait = max(wait, min(ra, maxRetryWait))
			}
			log.Printf("Artifact: %s attempt %d failed (%v); retrying in %v", s.ID, attempt-1, err, wait)
			if serr := sleepCtx(ctx, wait); serr != nil {
				err = fmt.Errorf("%w (while waiting to retry after: %v)", serr, err)
				break
			}
		}
		err = withRetrier(ctx, retry, func() error { return downloadVerified(ctx, c, s, path) })
		if err == nil || !transient(ctx, err) {
			break
		}
	}
	if err != nil {
		_ = os.Remove(path)
		return describe(s, err)
	}
	log.Printf("Artifact: %s verified (%d bytes) in %v", s.ID, s.Size, time.Since(start).Round(time.Millisecond))
	return nil
}

func withRetrier(ctx context.Context, retry AuthRetrier, fn func() error) error {
	if retry == nil {
		return fn()
	}
	return retry(ctx, fn)
}

// mismatchError is a verified download that isn't the expected file. It is
// never retried: the stored object is wrong, or someone changed it.
type mismatchError struct{ msg string }

func (e *mismatchError) Error() string { return e.msg }

// downloadVerified makes one attempt: it (re)creates the file, streams the
// object into it while hashing, then checks size and hash.
func downloadVerified(ctx context.Context, c *supabase.Client, s Spec, path string) error {
	// #nosec G304 - path is dir + a filename that Validate restricted to a plain name
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}

	attemptCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	timer := time.AfterFunc(idleTimeout, func() { cancel(errStalled) })
	defer timer.Stop()

	hash := sha256.New()
	w := &idleWriter{w: io.MultiWriter(f, hash), timer: timer}
	// Size+1 makes an oversize body fail with ErrTooLarge instead of being
	// cut at Size and looking complete.
	n, dlErr := c.Download(attemptCtx, s.Bucket, escapePath(s.Path), true, w, s.Size+1)
	closeErr := f.Close()

	if dlErr != nil {
		if errors.Is(context.Cause(attemptCtx), errStalled) && ctx.Err() == nil {
			return fmt.Errorf("%w for %v", errStalled, idleTimeout)
		}
		if errors.Is(dlErr, supabase.ErrTooLarge) {
			return &mismatchError{fmt.Sprintf("size mismatch: expected %d bytes, got more", s.Size)}
		}
		return dlErr
	}
	if closeErr != nil {
		return fmt.Errorf("close file: %w", closeErr)
	}
	if n != s.Size {
		return &mismatchError{fmt.Sprintf("size mismatch: expected %d bytes, got %d", s.Size, n)}
	}
	if got := hex.EncodeToString(hash.Sum(nil)); got != s.SHA256 {
		return &mismatchError{fmt.Sprintf("sha256 mismatch: expected %s, got %s", s.SHA256, got)}
	}
	return nil
}

// escapePath escapes each segment of an object name for the request URL
// (supabase.Client.StorageURL concatenates it verbatim), so names with
// spaces or '#' reach the right object.
func escapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		segs[i] = url.PathEscape(seg)
	}
	return strings.Join(segs, "/")
}

// idleWriter pushes the idle watchdog back on every write.
type idleWriter struct {
	w     io.Writer
	timer *time.Timer
}

func (iw *idleWriter) Write(p []byte) (int, error) {
	iw.timer.Reset(idleTimeout)
	return iw.w.Write(p)
}

// transient reports whether a failed attempt is worth repeating: network
// errors, stalls, 5xx, 408 and 429. Auth, permission, missing-object and
// mismatch errors are final, as is the task context ending.
func transient(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	var mm *mismatchError
	if errors.As(err, &mm) {
		return false
	}
	if errors.Is(err, errStalled) {
		return true
	}
	if status := supabase.StatusCode(err); status != 0 {
		return status >= 500 || status == http.StatusRequestTimeout || status == http.StatusTooManyRequests
	}
	// No HTTP status: a network error, unless it's a local file problem.
	var pathErr *os.PathError
	return !errors.As(err, &pathErr)
}

// describe turns a final error into the message the task note shows.
func describe(s Spec, err error) error {
	switch {
	case supabase.IsForbidden(err), supabase.IsNotFound(err):
		return fmt.Errorf("agent is not allowed to read artifact %s (task older than 7 days, or RLS missing on the server): %w", s.ID, err)
	default:
		return fmt.Errorf("artifact %s (%s): %w", s.ID, s.Filename, err)
	}
}

// sleepCtx waits for d or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
