package artifact

// White-box tests for Fetch and downloadArtifact using httptest mocks.
// Uses package artifact (not artifact_test) to access unexported helpers.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/supabase"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func makeSpec(id string, content []byte) Spec {
	h := sha256.Sum256(content)
	return Spec{
		ID:       id,
		Bucket:   "app-installers",
		Path:     "artifacts/" + id + ".bin",
		Filename: id + ".bin",
		SHA256:   hex.EncodeToString(h[:]),
		Size:     int64(len(content)),
	}
}

// artifactServer serves content for every request.
func artifactServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *supabase.Client) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	cfg := &config.Config{SupabaseURL: srv.URL, SupabaseKey: "test-key"}
	c := supabase.FromConfig(cfg, supabase.WithHTTPClient(srv.Client()))
	return srv, c
}

// fakeRetrier implements AuthRetrier. refreshErr controls whether the refresh
// succeeds; calls counts how many times RefreshToken was called.
type fakeRetrier struct {
	calls      int
	refreshErr error
}

func (r *fakeRetrier) RefreshToken(_ context.Context) error {
	r.calls++
	return r.refreshErr
}

// ── Fetch: happy path ─────────────────────────────────────────────────────────

func TestFetch_HappyPath(t *testing.T) {
	content := []byte("fake installer binary content")
	spec := makeSpec("installer", content)

	_, c := artifactServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(content)
	})

	dir := t.TempDir()
	paths, err := Fetch(context.Background(), c, nil, dir, []Spec{spec})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if paths["installer"] == "" {
		t.Fatal("expected path for 'installer' key")
	}
	got, _ := os.ReadFile(paths["installer"])
	if !bytes.Equal(got, content) {
		t.Errorf("file content = %q, want %q", got, content)
	}
}

func TestFetch_ReturnsAbsolutePaths(t *testing.T) {
	content := []byte("data")
	spec := makeSpec("pkg", content)

	_, c := artifactServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(content)
	})

	paths, err := Fetch(context.Background(), c, nil, t.TempDir(), []Spec{spec})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !filepath.IsAbs(paths["pkg"]) {
		t.Errorf("path %q is not absolute", paths["pkg"])
	}
}

// ── Fetch: size mismatch ──────────────────────────────────────────────────────

func TestFetch_SizeTooSmall_FileRemoved(t *testing.T) {
	content := []byte("short")
	spec := makeSpec("installer", content)
	spec.Size = int64(len(content)) + 10 // claim larger size

	_, c := artifactServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(content)
	})

	dir := t.TempDir()
	_, err := Fetch(context.Background(), c, nil, dir, []Spec{spec})
	if err == nil {
		t.Fatal("expected error for size mismatch, got nil")
	}
	destPath := filepath.Join(dir, spec.Filename)
	if _, statErr := os.Stat(destPath); !os.IsNotExist(statErr) {
		t.Error("partial file must be removed after size mismatch")
	}
}

func TestFetch_SizeTooLarge_FileRemoved(t *testing.T) {
	content := []byte("too much data here")
	spec := makeSpec("installer", content)
	spec.Size = int64(len(content)) - 5 // claim smaller size

	_, c := artifactServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(content)
	})

	dir := t.TempDir()
	_, err := Fetch(context.Background(), c, nil, dir, []Spec{spec})
	if err == nil {
		t.Fatal("expected error for oversized download, got nil")
	}
	destPath := filepath.Join(dir, spec.Filename)
	if _, statErr := os.Stat(destPath); !os.IsNotExist(statErr) {
		t.Error("partial file must be removed after oversize error")
	}
}

// ── Fetch: hash mismatch ──────────────────────────────────────────────────────

func TestFetch_HashMismatch_FileRemoved(t *testing.T) {
	content := []byte("correct content")
	spec := makeSpec("installer", content)
	spec.SHA256 = "0000000000000000000000000000000000000000000000000000000000000000" // wrong hash

	_, c := artifactServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(content)
	})

	dir := t.TempDir()
	_, err := Fetch(context.Background(), c, nil, dir, []Spec{spec})
	if err == nil {
		t.Fatal("expected hash mismatch error, got nil")
	}
	if !containsAny(err.Error(), "hash mismatch") {
		t.Errorf("error %q does not mention hash mismatch", err)
	}
	destPath := filepath.Join(dir, spec.Filename)
	if _, statErr := os.Stat(destPath); !os.IsNotExist(statErr) {
		t.Error("file must be removed after hash mismatch")
	}
}

// ── Fetch: 401 → token refresh → success ─────────────────────────────────────

func TestFetch_401_RecoveredByRetrier(t *testing.T) {
	content := []byte("recovered content")
	spec := makeSpec("installer", content)

	var served atomic.Int32
	_, c := artifactServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := served.Add(1)
		if n == 1 {
			// First request: return 401 InvalidJWT
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"statusCode":"400","error":"InvalidJWT","message":"jwt expired"}`))
			return
		}
		_, _ = w.Write(content)
	})

	retrier := &fakeRetrier{}
	paths, err := Fetch(context.Background(), c, retrier, t.TempDir(), []Spec{spec})
	if err != nil {
		t.Fatalf("Fetch after 401 recovery: %v", err)
	}
	if retrier.calls != 1 {
		t.Errorf("retrier.calls = %d, want 1", retrier.calls)
	}
	got, _ := os.ReadFile(paths["installer"])
	if !bytes.Equal(got, content) {
		t.Errorf("content = %q, want %q", got, content)
	}
}

func TestFetch_401_NoRetrier_Fails(t *testing.T) {
	content := []byte("data")
	spec := makeSpec("installer", content)

	_, c := artifactServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"statusCode":"400","error":"InvalidJWT","message":"jwt expired"}`))
	})

	_, err := Fetch(context.Background(), c, nil, t.TempDir(), []Spec{spec})
	if err == nil {
		t.Fatal("expected error for 401 with no retrier, got nil")
	}
}

// ── Fetch: 403 not retried ────────────────────────────────────────────────────

func TestFetch_403_NotRetried(t *testing.T) {
	content := []byte("data")
	spec := makeSpec("installer", content)

	var calls atomic.Int32
	_, c := artifactServer(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"forbidden"}`))
	})

	_, err := Fetch(context.Background(), c, &fakeRetrier{}, t.TempDir(), []Spec{spec})
	if err == nil {
		t.Fatal("expected error for 403, got nil")
	}
	if calls.Load() != 1 {
		t.Errorf("server called %d times, want exactly 1 (no retry on 403)", calls.Load())
	}
}

// ── Fetch: 404 not retried ────────────────────────────────────────────────────

func TestFetch_404_NotRetried(t *testing.T) {
	content := []byte("data")
	spec := makeSpec("installer", content)

	var calls atomic.Int32
	_, c := artifactServer(t, func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not_found","message":"object not found"}`))
	})

	_, err := Fetch(context.Background(), c, nil, t.TempDir(), []Spec{spec})
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
	if calls.Load() != 1 {
		t.Errorf("server called %d times, want exactly 1 (no retry on 404)", calls.Load())
	}
	if !containsAny(err.Error(), "not allowed") {
		t.Errorf("error %q should mention 'not allowed'", err)
	}
}

// ── Fetch: 500, 500, 200 succeeds on 3rd attempt ─────────────────────────────

func TestFetch_500_RetriesAndSucceeds(t *testing.T) {
	content := []byte("retry success content")
	spec := makeSpec("installer", content)

	var calls atomic.Int32
	_, c := artifactServer(t, func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"internal error"}`))
			return
		}
		_, _ = w.Write(content)
	})

	// Override retryBaseDelay to zero so test doesn't sleep 3s.
	origDelay := retryBaseDelay
	retryBaseDelay = time.Millisecond
	t.Cleanup(func() { retryBaseDelay = origDelay })

	paths, err := Fetch(context.Background(), c, nil, t.TempDir(), []Spec{spec})
	if err != nil {
		t.Fatalf("Fetch after 2x500: %v", err)
	}
	if calls.Load() != 3 {
		t.Errorf("server calls = %d, want 3", calls.Load())
	}
	got, _ := os.ReadFile(paths["installer"])
	if !bytes.Equal(got, content) {
		t.Errorf("content mismatch after retry")
	}
}

// ── Fetch: context cancel ─────────────────────────────────────────────────────

func TestFetch_ContextCancelled(t *testing.T) {
	content := []byte("data")
	spec := makeSpec("installer", content)

	_, c := artifactServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	origDelay := retryBaseDelay
	retryBaseDelay = 50 * time.Millisecond
	t.Cleanup(func() { retryBaseDelay = origDelay })

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel immediately so the retry wait is interrupted.
	cancel()

	_, err := Fetch(ctx, c, nil, t.TempDir(), []Spec{spec})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// ── Fetch: previously downloaded files cleaned up on later failure ────────────

func TestFetch_CleanupOnPartialSuccess(t *testing.T) {
	good := []byte("good content")
	bad := []byte("bad content")
	specA := makeSpec("first", good)
	specB := makeSpec("second", bad)
	// Wrong hash for second artifact
	specB.SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"

	var calls atomic.Int32
	_, c := artifactServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			_, _ = w.Write(good)
		} else {
			_, _ = w.Write(bad)
		}
	})

	dir := t.TempDir()
	_, err := Fetch(context.Background(), c, nil, dir, []Spec{specA, specB})
	if err == nil {
		t.Fatal("expected error when second artifact has hash mismatch, got nil")
	}
	// Both files must have been cleaned up.
	for _, sp := range []Spec{specA, specB} {
		p := filepath.Join(dir, sp.Filename)
		if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
			t.Errorf("file %s should have been cleaned up but still exists", p)
		}
	}
}

// ── isTransient ───────────────────────────────────────────────────────────────

func TestIsTransient(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"fatal", &errFatal{errors.New("size mismatch")}, false},
		{"network error", errors.New("connection reset"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isTransient(tt.err)
			if got != tt.want {
				t.Errorf("isTransient(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
