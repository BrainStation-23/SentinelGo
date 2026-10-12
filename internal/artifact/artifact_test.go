package artifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sentinelgo/internal/supabase"
)

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func spec(id string, body []byte) Spec {
	return Spec{
		ID:       id,
		Bucket:   "app-installers",
		Path:     "artifacts/7f3c/" + id + ".msi",
		Filename: id + ".msi",
		SHA256:   sum(body),
		Size:     int64(len(body)),
	}
}

// fastTimings shrinks the retry and watchdog timings for the test.
func fastTimings(t *testing.T) {
	t.Helper()
	oldIdle, oldBackoff := idleTimeout, retryBackoff
	idleTimeout = 200 * time.Millisecond
	retryBackoff = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { idleTimeout, retryBackoff = oldIdle, oldBackoff })
}

// server answers storage downloads with handle and counts requests.
func server(t *testing.T, handle http.HandlerFunc) (*supabase.Client, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		handle(w, r)
	}))
	t.Cleanup(srv.Close)
	c := supabase.New(srv.URL, "anon", func() string { return "jwt" }, supabase.WithHTTPClient(srv.Client()))
	return c, &hits
}

func serveBytes(body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }
}

func assertNoFiles(t *testing.T, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("files left behind in %s: %v", dir, names)
	}
}

// ── Validate ─────────────────────────────────────────────────────────────────

func TestValidate_AcceptsContractExample(t *testing.T) {
	s := Spec{
		ID:       "installer",
		Bucket:   "app-installers",
		Path:     "artifacts/7f3c9a2e-1/ZoomInstallerFull.msi",
		Filename: "ZoomInstallerFull.msi",
		SHA256:   "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		Size:     104857600,
	}
	if err := Validate([]Spec{s}); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := Validate(nil); err != nil {
		t.Fatalf("Validate(nil): %v", err)
	}
}

func TestValidate_Rules(t *testing.T) {
	good := spec("installer", []byte("x"))
	tests := []struct {
		name string
		mod  func(*Spec)
		want string
	}{
		{"id uppercase", func(s *Spec) { s.ID = "Installer" }, "invalid id"},
		{"id starts with digit", func(s *Spec) { s.ID = "1x" }, "invalid id"},
		{"id empty", func(s *Spec) { s.ID = "" }, "invalid id"},
		{"id too long", func(s *Spec) { s.ID = "a" + strings.Repeat("b", 32) }, "invalid id"},
		{"id dash", func(s *Spec) { s.ID = "a-b" }, "invalid id"},
		{"bucket", func(s *Spec) { s.Bucket = "command-scripts" }, "not allowed"},
		{"path empty", func(s *Spec) { s.Path = "" }, "path is empty"},
		{"path leading slash", func(s *Spec) { s.Path = "/artifacts/x.msi" }, "must not start with /"},
		{"path dotdot", func(s *Spec) { s.Path = "artifacts/../other/x.msi" }, ".. segment"},
		{"path dotdot backslash", func(s *Spec) { s.Path = `artifacts\..\x.msi` }, ".. segment"},
		{"path empty segment", func(s *Spec) { s.Path = "artifacts//x.msi" }, "empty or . segment"},
		{"path dot segment", func(s *Spec) { s.Path = "artifacts/./x.msi" }, "empty or . segment"},
		{"path trailing slash", func(s *Spec) { s.Path = "artifacts/x/" }, "empty or . segment"},
		{"filename trailing dot", func(s *Spec) { s.Filename = "x.msi." }, "ends in a dot or space"},
		{"filename trailing space", func(s *Spec) { s.Filename = "x.msi " }, "ends in a dot or space"},
		{"filename slash", func(s *Spec) { s.Filename = "a/b.msi" }, "invalid filename"},
		{"filename traversal", func(s *Spec) { s.Filename = "../b.msi" }, "invalid filename"},
		{"filename dot", func(s *Spec) { s.Filename = "." }, "invalid filename"},
		{"filename dotdot", func(s *Spec) { s.Filename = ".." }, "invalid filename"},
		{"filename empty", func(s *Spec) { s.Filename = "" }, "invalid filename"},
		{"filename colon", func(s *Spec) { s.Filename = "c:x.msi" }, "invalid filename"},
		{"filename too long", func(s *Spec) { s.Filename = strings.Repeat("a", 129) }, "invalid filename"},
		{"filename device", func(s *Spec) { s.Filename = "nul.msi" }, "reserved device name"},
		{"filename device bare", func(s *Spec) { s.Filename = "COM1" }, "reserved device name"},
		{"sha256 upper", func(s *Spec) { s.SHA256 = strings.ToUpper(s.SHA256) }, "sha256"},
		{"sha256 short", func(s *Spec) { s.SHA256 = s.SHA256[:63] }, "sha256"},
		{"size zero", func(s *Spec) { s.Size = 0 }, "size"},
		{"size over 4 GiB", func(s *Spec) { s.Size = MaxSize + 1 }, "size"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := good
			tt.mod(&s)
			err := Validate([]Spec{s})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tt.want)
			}
		})
	}
}

func TestValidate_SizeAtLimitOK(t *testing.T) {
	s := spec("installer", []byte("x"))
	s.Size = MaxSize
	if err := Validate([]Spec{s}); err != nil {
		t.Fatalf("Validate at 4 GiB: %v", err)
	}
}

func TestValidate_ListRules(t *testing.T) {
	a := spec("a", []byte("a"))
	b := spec("b", []byte("b"))

	six := make([]Spec, 6)
	for i := range six {
		six[i] = spec(string(rune('a'+i)), []byte{byte(i)})
	}
	if err := Validate(six); err == nil || !strings.Contains(err.Error(), "at most 5") {
		t.Errorf("6 specs: err = %v", err)
	}

	dupID := b
	dupID.ID = "a"
	if err := Validate([]Spec{a, dupID}); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Errorf("duplicate id: err = %v", err)
	}

	dupName := b
	dupName.Filename = strings.ToUpper(a.Filename)
	if err := Validate([]Spec{a, dupName}); err == nil || !strings.Contains(err.Error(), "filename") {
		t.Errorf("duplicate filename: err = %v", err)
	}
}

// ── Fetch ────────────────────────────────────────────────────────────────────

func TestFetch_HappyPath(t *testing.T) {
	bodies := map[string][]byte{
		"/storage/v1/object/authenticated/app-installers/artifacts/7f3c/installer.msi": []byte("installer bytes"),
		"/storage/v1/object/authenticated/app-installers/artifacts/7f3c/config.msi":    []byte("config bytes"),
	}
	c, hits := server(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer jwt" {
			t.Errorf("Authorization = %q", got)
		}
		body, ok := bodies[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	})
	specs := []Spec{spec("installer", []byte("installer bytes")), spec("config", []byte("config bytes"))}
	dir := filepath.Join(t.TempDir(), "artifacts")

	paths, err := Fetch(context.Background(), c, nil, dir, specs)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if hits.Load() != 2 {
		t.Errorf("requests = %d, want 2", hits.Load())
	}
	for _, s := range specs {
		p := paths[s.ID]
		if !filepath.IsAbs(p) || filepath.Base(p) != s.Filename {
			t.Errorf("path[%s] = %q", s.ID, p)
		}
		got, err := os.ReadFile(p)
		if err != nil || sum(got) != s.SHA256 {
			t.Errorf("%s content wrong: %v", s.ID, err)
		}
		if runtime.GOOS != "windows" {
			if fi, _ := os.Stat(p); fi.Mode().Perm() != 0600 {
				t.Errorf("%s mode = %v, want 0600", s.ID, fi.Mode().Perm())
			}
		}
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0700 {
			t.Errorf("dir mode = %v, want 0700", fi.Mode().Perm())
		}
	}
}

func TestFetch_NoSpecs(t *testing.T) {
	paths, err := Fetch(context.Background(), nil, nil, t.TempDir(), nil)
	if err != nil || len(paths) != 0 {
		t.Fatalf("Fetch(nil) = %v, %v", paths, err)
	}
}

func TestFetch_InvalidSpec_NoRequest(t *testing.T) {
	c, hits := server(t, serveBytes([]byte("x")))
	s := spec("installer", []byte("x"))
	s.Bucket = "other"
	if _, err := Fetch(context.Background(), c, nil, t.TempDir(), []Spec{s}); err == nil {
		t.Fatal("Fetch succeeded with an invalid spec")
	}
	if hits.Load() != 0 {
		t.Errorf("requests = %d, want 0", hits.Load())
	}
}

func TestFetch_EscapesPath(t *testing.T) {
	var gotPath string
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		_, _ = w.Write([]byte("x"))
	})
	s := spec("installer", []byte("x"))
	s.Path = "artifacts/7f3c/Zoom Installer#1.msi"
	if _, err := Fetch(context.Background(), c, nil, t.TempDir(), []Spec{s}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if want := "/storage/v1/object/authenticated/app-installers/artifacts/7f3c/Zoom%20Installer%231.msi"; gotPath != want {
		t.Errorf("path = %q, want %q", gotPath, want)
	}
}

func TestFetch_Mismatch_RemovesFile_NoRetry(t *testing.T) {
	fastTimings(t)
	want := []byte("the real installer")
	tests := []struct {
		name    string
		served  []byte
		wantErr string
	}{
		{"too small", want[:5], "size mismatch"},
		{"too large", append(append([]byte{}, want...), "extra"...), "size mismatch"},
		{"hash mismatch", []byte("the fake installer"), "sha256 mismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, hits := server(t, serveBytes(tt.served))
			dir := t.TempDir()
			_, err := Fetch(context.Background(), c, nil, dir, []Spec{spec("installer", want)})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) || !strings.Contains(err.Error(), "installer") {
				t.Fatalf("err = %v, want %q naming the artifact", err, tt.wantErr)
			}
			if hits.Load() != 1 {
				t.Errorf("requests = %d, want 1 (no retry on mismatch)", hits.Load())
			}
			assertNoFiles(t, dir)
		})
	}
}

func TestFetch_LaterFailureRemovesEarlierFiles(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/first.msi") {
			_, _ = w.Write([]byte("first"))
			return
		}
		_, _ = w.Write([]byte("tampered"))
	})
	dir := t.TempDir()
	_, err := Fetch(context.Background(), c, nil, dir, []Spec{spec("first", []byte("first")), spec("second", []byte("second"))})
	if err == nil {
		t.Fatal("Fetch succeeded")
	}
	assertNoFiles(t, dir)
}

func TestFetch_401RecoveredByRetrier(t *testing.T) {
	var n atomic.Int32
	c, hits := server(t, func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"InvalidJWT","message":"jwt expired"}`))
			return
		}
		_, _ = w.Write([]byte("x"))
	})
	var recovered int
	retry := func(ctx context.Context, fn func() error) error {
		err := fn()
		if supabase.IsUnauthorized(err) {
			recovered++
			err = fn()
		}
		return err
	}
	if _, err := Fetch(context.Background(), c, retry, t.TempDir(), []Spec{spec("installer", []byte("x"))}); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if recovered != 1 || hits.Load() != 2 {
		t.Errorf("recovered = %d, requests = %d; want 1 and 2", recovered, hits.Load())
	}
}

func TestFetch_401WithoutRetrier_NotRetried(t *testing.T) {
	fastTimings(t)
	c, hits := server(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	if _, err := Fetch(context.Background(), c, nil, t.TempDir(), []Spec{spec("installer", []byte("x"))}); !supabase.IsUnauthorized(err) {
		t.Fatalf("err = %v, want a 401", err)
	}
	if hits.Load() != 1 {
		t.Errorf("requests = %d, want 1", hits.Load())
	}
}

func TestFetch_ForbiddenAndNotFound_NotRetried(t *testing.T) {
	fastTimings(t)
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			c, hits := server(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) })
			dir := t.TempDir()
			_, err := Fetch(context.Background(), c, nil, dir, []Spec{spec("installer", []byte("x"))})
			if err == nil || !strings.Contains(err.Error(), "agent is not allowed to read artifact installer") {
				t.Fatalf("err = %v", err)
			}
			if supabase.StatusCode(err) != status {
				t.Errorf("status = %d, want %d kept in the chain", supabase.StatusCode(err), status)
			}
			if hits.Load() != 1 {
				t.Errorf("requests = %d, want 1", hits.Load())
			}
			assertNoFiles(t, dir)
		})
	}
}

func TestFetch_TransientThenSuccess(t *testing.T) {
	fastTimings(t)
	for _, status := range []int{http.StatusInternalServerError, http.StatusRequestTimeout, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var n atomic.Int32
			c, hits := server(t, func(w http.ResponseWriter, _ *http.Request) {
				if n.Add(1) < 3 {
					w.WriteHeader(status)
					_, _ = w.Write([]byte("partial garbage"))
					return
				}
				_, _ = w.Write([]byte("x"))
			})
			paths, err := Fetch(context.Background(), c, nil, t.TempDir(), []Spec{spec("installer", []byte("x"))})
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if hits.Load() != 3 {
				t.Errorf("requests = %d, want 3", hits.Load())
			}
			if got, _ := os.ReadFile(paths["installer"]); string(got) != "x" {
				t.Errorf("content = %q, want the file truncated between attempts", got)
			}
		})
	}
}

func TestFetch_TransientGivesUpAfterThreeAttempts(t *testing.T) {
	fastTimings(t)
	c, hits := server(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	dir := t.TempDir()
	if _, err := Fetch(context.Background(), c, nil, dir, []Spec{spec("installer", []byte("x"))}); supabase.StatusCode(err) != http.StatusBadGateway {
		t.Fatalf("err = %v, want the 502", err)
	}
	if hits.Load() != 3 {
		t.Errorf("requests = %d, want 3", hits.Load())
	}
	assertNoFiles(t, dir)
}

// stallHandler sends a few bytes, then nothing until the client gives up.
func stallHandler(release <-chan struct{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("abc"))
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}
}

func TestFetch_IdleStallAborts(t *testing.T) {
	fastTimings(t)
	release := make(chan struct{})
	c, hits := server(t, stallHandler(release))
	t.Cleanup(func() { close(release) })

	dir := t.TempDir()
	start := time.Now()
	_, err := Fetch(context.Background(), c, nil, dir, []Spec{spec("installer", make([]byte, 100))})
	if err == nil || !errors.Is(err, errStalled) {
		t.Fatalf("err = %v, want a stall", err)
	}
	if hits.Load() != 3 {
		t.Errorf("requests = %d, want 3 (a stall is retried)", hits.Load())
	}
	if time.Since(start) > 10*time.Second {
		t.Errorf("stall took %v to abort", time.Since(start))
	}
	assertNoFiles(t, dir)
}

func TestFetch_ContextCancel(t *testing.T) {
	fastTimings(t)
	idleTimeout = time.Minute
	release := make(chan struct{})
	c, hits := server(t, stallHandler(release))
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	dir := t.TempDir()
	_, err := Fetch(ctx, c, nil, dir, []Spec{spec("installer", make([]byte, 100))})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if hits.Load() != 1 {
		t.Errorf("requests = %d, want 1 (cancel is final)", hits.Load())
	}
	assertNoFiles(t, dir)
}

func TestFetch_NotEnoughDiskSpace(t *testing.T) {
	old := diskFree
	t.Cleanup(func() { diskFree = old })
	var asked string
	diskFree = func(dir string) (uint64, error) { asked = dir; return 1099, nil }

	c, hits := server(t, serveBytes(make([]byte, 1000)))
	dir := filepath.Join(t.TempDir(), "artifacts")
	s := spec("installer", make([]byte, 1000))

	_, err := Fetch(context.Background(), c, nil, dir, []Spec{s})
	if err == nil || !strings.Contains(err.Error(), "not enough disk space") {
		t.Fatalf("err = %v, want a disk space error", err)
	}
	if hits.Load() != 0 {
		t.Errorf("requests = %d, want 0", hits.Load())
	}
	if asked != dir {
		t.Errorf("checked %q, want %q", asked, dir)
	}

	// sum + 10% exactly is enough.
	diskFree = func(string) (uint64, error) { return 1100, nil }
	if _, err := Fetch(context.Background(), c, nil, dir, []Spec{s}); err != nil {
		t.Fatalf("Fetch with exactly enough space: %v", err)
	}
}

func TestFreeBytes_Real(t *testing.T) {
	free, err := freeBytes(t.TempDir())
	if err != nil || free == 0 {
		t.Fatalf("freeBytes = %d, %v", free, err)
	}
}

// TestFetch_LargeFileFlatMemory streams a 2 GiB object and checks the heap
// never grows by more than a few MB. Skipped with -short (CI): it writes 2 GiB.
func TestFetch_LargeFileFlatMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 2 GiB to disk")
	}
	const size = 2 << 30
	chunk := make([]byte, 1<<20)
	for i := range chunk {
		chunk[i] = byte(i * 7)
	}
	h := sha256.New()
	for written := 0; written < size; written += len(chunk) {
		h.Write(chunk)
	}
	s := spec("installer", nil)
	s.Size = size
	s.SHA256 = hex.EncodeToString(h.Sum(nil))

	c, _ := server(t, func(w http.ResponseWriter, _ *http.Request) {
		for written := 0; written < size; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})

	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var peak atomic.Uint64
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		var m runtime.MemStats
		for {
			select {
			case <-done:
				return
			case <-time.After(50 * time.Millisecond):
				runtime.ReadMemStats(&m)
				if m.HeapInuse > peak.Load() {
					peak.Store(m.HeapInuse)
				}
			}
		}
	}()

	_, err := Fetch(context.Background(), c, nil, t.TempDir(), []Spec{s})
	close(done)
	wg.Wait()
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	growth := int64(peak.Load()) - int64(base.HeapInuse)
	t.Logf("heap in use grew by %d KiB", growth>>10)
	if growth > 16<<20 {
		t.Errorf("heap grew by %d bytes streaming 2 GiB, want under 16 MiB", growth)
	}
}
