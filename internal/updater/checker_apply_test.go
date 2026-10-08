package updater

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"sentinelgo/internal/config"
)

// ── CheckAndApply end-to-end (hermetic) ───────────────────────────────────────
//
// These tests drive the full update path against a fake Supabase (RPC +
// Storage) with a test signing key. executablePath points at a fake binary in
// t.TempDir() and restartFn is stubbed, so nothing outside the temp dir is
// touched and the process never exits.

const releaseAsset = "v99.9.9/sentinelgo-test"

type updateFixture struct {
	self       string // fake running binary
	oldBinary  []byte
	newBinary  []byte
	restarted  []string // newPath values passed to restartFn
	restartErr error
}

// newUpdateFixture wires config.Version, PublicKey, executablePath and
// restartFn for one test. The release's advertised SHA256 is sha256(newBinary)
// unless manifestSHA is non-empty.
func newUpdateFixture(t *testing.T, manifestSHA string) (*updateFixture, *config.Config) {
	t.Helper()
	f := &updateFixture{oldBinary: []byte("old agent v1.0.0"), newBinary: []byte("new agent v99.9.9")}
	f.self = fakeExecutable(t, f.oldBinary)

	prevVersion := config.Version
	config.Version = "v1.0.0"
	t.Cleanup(func() { config.Version = prevVersion })

	pub, priv := newTestKeypair(t)
	prevKey := PublicKey
	PublicKey = pub
	t.Cleanup(func() { PublicKey = prevKey })

	prevRestart := restartFn
	restartFn = func(newPath string) error {
		f.restarted = append(f.restarted, newPath)
		return f.restartErr
	}
	t.Cleanup(func() { restartFn = prevRestart })

	sum := sha256.Sum256(f.newBinary)
	if manifestSHA == "" {
		manifestSHA = hex.EncodeToString(sum[:])
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, f.newBinary))
	release := LatestRelease{Version: "v99.9.9", AssetPath: releaseAsset, SHA256: manifestSHA}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case rpcPath:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]LatestRelease{release})
		case "/storage/v1/object/agent-releases/" + releaseAsset:
			_, _ = w.Write(f.newBinary)
		case "/storage/v1/object/agent-releases/" + releaseAsset + ".sig":
			_, _ = w.Write([]byte(sig))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	cfg := &config.Config{SupabaseURL: srv.URL, SupabaseKey: "test-key"}
	cfg.SetTokens("test-jwt", "")
	return f, cfg
}

func TestCheckAndApply_AppliesVerifiedUpdate(t *testing.T) {
	f, cfg := newUpdateFixture(t, "")

	if err := CheckAndApply(t.Context(), cfg); err != nil {
		t.Fatalf("CheckAndApply() error: %v", err)
	}

	staged := f.self + ".new"
	if len(f.restarted) != 1 || f.restarted[0] != staged {
		t.Fatalf("restart calls = %q, want exactly [%q]", f.restarted, staged)
	}
	assertNotExist(t, f.self+".backup", "backup")

	if runtime.GOOS == "windows" {
		// Windows defers the swap to the restart script: the running binary is
		// untouched and the verified binary is staged next to it.
		if got := mustReadFile(t, f.self); !bytes.Equal(got, f.oldBinary) {
			t.Errorf("self replaced in-process on Windows: %q", got)
		}
		if got := mustReadFile(t, staged); !bytes.Equal(got, f.newBinary) {
			t.Errorf("staged binary = %q, want %q", got, f.newBinary)
		}
		return
	}
	if got := mustReadFile(t, f.self); !bytes.Equal(got, f.newBinary) {
		t.Errorf("self = %q, want the new binary %q", got, f.newBinary)
	}
	assertNotExist(t, staged, "staged binary")
}

func TestCheckAndApply_RestartErrorIsReturned(t *testing.T) {
	f, cfg := newUpdateFixture(t, "")
	f.restartErr = errors.New("restart failed")

	if err := CheckAndApply(t.Context(), cfg); !errors.Is(err, f.restartErr) {
		t.Errorf("CheckAndApply() error = %v, want %v", err, f.restartErr)
	}
}

func TestCheckAndApply_AlreadyUpToDate(t *testing.T) {
	f, cfg := newUpdateFixture(t, "")
	config.Version = "v99.9.9"

	if err := CheckAndApply(t.Context(), cfg); err != nil {
		t.Fatalf("CheckAndApply() error: %v", err)
	}
	if len(f.restarted) != 0 {
		t.Errorf("restart must not run when already up to date")
	}
	assertNotExist(t, f.self+".backup", "backup")
}

func TestCheckAndApply_BackupFailureRefusesUpdate(t *testing.T) {
	f, cfg := newUpdateFixture(t, "")
	failExecutablePath(t)

	err := CheckAndApply(t.Context(), cfg)
	if err == nil || !strings.Contains(err.Error(), "without a backup") {
		t.Fatalf("CheckAndApply() error = %v, want a refuse-without-backup error", err)
	}
	if len(f.restarted) != 0 {
		t.Error("restart must not run when the backup fails")
	}
}

func TestCheckAndApply_DownloadFailureRemovesBackup(t *testing.T) {
	f, cfg := newUpdateFixture(t, "")
	// The signature no longer matches the agent's trusted key.
	wrongKey, _ := newTestKeypair(t)
	PublicKey = wrongKey

	err := CheckAndApply(t.Context(), cfg)
	if err == nil || !strings.Contains(err.Error(), "download and verify failed") {
		t.Fatalf("CheckAndApply() error = %v, want a download/verify error", err)
	}
	if got := mustReadFile(t, f.self); !bytes.Equal(got, f.oldBinary) {
		t.Errorf("self must be untouched, got %q", got)
	}
	assertNotExist(t, f.self+".backup", "backup")
	assertNotExist(t, f.self+".new", "staged binary")
	if len(f.restarted) != 0 {
		t.Error("restart must not run when verification fails")
	}
}

func TestCheckAndApply_ChecksumMismatchRemovesBackup(t *testing.T) {
	f, cfg := newUpdateFixture(t, strings.Repeat("0", 64))

	err := CheckAndApply(t.Context(), cfg)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("CheckAndApply() error = %v, want a checksum mismatch", err)
	}
	if got := mustReadFile(t, f.self); !bytes.Equal(got, f.oldBinary) {
		t.Errorf("self must be untouched, got %q", got)
	}
	assertNotExist(t, f.self+".backup", "backup")
	assertNotExist(t, f.self+".new", "staged binary") // #116
	if len(f.restarted) != 0 {
		t.Error("restart must not run on a checksum mismatch")
	}
}

func TestCheckAndApply_ReplaceFailureRollsBack(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not replace in-process; the swap happens in the restart script")
	}
	f, cfg := newUpdateFixture(t, "")
	blockPath(t, filepath.Join(filepath.Dir(f.self), ".sentinelgo_update_tmp"))

	err := CheckAndApply(t.Context(), cfg)
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("CheckAndApply() error = %v, want a rolled-back error", err)
	}
	if got := mustReadFile(t, f.self); !bytes.Equal(got, f.oldBinary) {
		t.Errorf("self = %q, want the restored old binary", got)
	}
	assertNotExist(t, f.self+".backup", "backup")
	if len(f.restarted) != 0 {
		t.Error("restart must not run after a failed replace")
	}
}

func TestCheckAndApply_ReplaceAndRollbackFailureKeepsBackup(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not replace in-process; the swap happens in the restart script")
	}
	f, cfg := newUpdateFixture(t, "")
	blockPath(t, filepath.Join(filepath.Dir(f.self), ".sentinelgo_update_tmp"))
	blockPath(t, f.self+".rollback")

	err := CheckAndApply(t.Context(), cfg)
	if err == nil || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("CheckAndApply() error = %v, want a rollback-failed error", err)
	}
	if got := mustReadFile(t, f.self+".backup"); !bytes.Equal(got, f.oldBinary) {
		t.Errorf("backup must be kept for manual recovery, got %q", got)
	}
	if len(f.restarted) != 0 {
		t.Error("restart must not run after a failed replace")
	}
}

// ── CheckInternetConnectivity (fake dialer) ───────────────────────────────────

type closeErrConn struct{ net.Conn }

func (c closeErrConn) Close() error {
	_ = c.Conn.Close()
	return errors.New("close failed")
}

// fakeDial replaces dialTimeout. reachable lists the endpoints that connect;
// every attempted address is recorded in order.
func fakeDial(t *testing.T, closeErr bool, reachable ...string) *[]string {
	t.Helper()
	var dialed []string
	prev := dialTimeout
	dialTimeout = func(network, addr string, _ time.Duration) (net.Conn, error) {
		dialed = append(dialed, addr)
		for _, r := range reachable {
			if addr == r {
				c, other := net.Pipe()
				_ = other.Close()
				if closeErr {
					return closeErrConn{c}, nil
				}
				return c, nil
			}
		}
		return nil, errors.New("dial refused")
	}
	t.Cleanup(func() { dialTimeout = prev })
	return &dialed
}

func TestCheckInternetConnectivity_PrefersSupabaseHost(t *testing.T) {
	dialed := fakeDial(t, false, "abc.supabase.co:443")
	if !CheckInternetConnectivity("https://abc.supabase.co") {
		t.Fatal("want connectivity via the Supabase host")
	}
	if len(*dialed) != 1 || (*dialed)[0] != "abc.supabase.co:443" {
		t.Errorf("dialed = %q, want only the Supabase host", *dialed)
	}
}

func TestCheckInternetConnectivity_FallsBackToPublicHosts(t *testing.T) {
	dialed := fakeDial(t, false, "cloudflare.com:443")
	if !CheckInternetConnectivity("https://abc.supabase.co") {
		t.Fatal("want connectivity via a fallback host")
	}
	want := []string{"abc.supabase.co:443", "google.com:443", "cloudflare.com:443"}
	if strings.Join(*dialed, ",") != strings.Join(want, ",") {
		t.Errorf("dialed = %q, want %q", *dialed, want)
	}
}

func TestCheckInternetConnectivity_NoneReachable(t *testing.T) {
	dialed := fakeDial(t, false)
	if CheckInternetConnectivity("https://abc.supabase.co") {
		t.Fatal("want no connectivity when every dial fails")
	}
	if len(*dialed) != 3 {
		t.Errorf("dialed = %q, want 3 attempts", *dialed)
	}
}

func TestCheckInternetConnectivity_InvalidSupabaseURLSkipsHost(t *testing.T) {
	dialed := fakeDial(t, false)
	_ = CheckInternetConnectivity("://not a url")
	if len(*dialed) != 2 || (*dialed)[0] != "google.com:443" {
		t.Errorf("dialed = %q, want only the public fallbacks", *dialed)
	}
}

func TestCheckInternetConnectivity_CloseErrorStillConnected(t *testing.T) {
	fakeDial(t, true, "abc.supabase.co:443")
	if !CheckInternetConnectivity("https://abc.supabase.co") {
		t.Error("a close error after a successful dial must still count as connected")
	}
}

// ── StartupUpdateCheck ────────────────────────────────────────────────────────

func countingRPCServer(t *testing.T, status int, hits *int64) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == rpcPath {
			atomic.AddInt64(hits, 1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte("[]"))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestStartupUpdateCheck_NoConnectivitySkips(t *testing.T) {
	fakeDial(t, false)
	var hits int64
	srv := countingRPCServer(t, http.StatusOK, &hits)

	if err := StartupUpdateCheck(t.Context(), &config.Config{SupabaseURL: srv.URL, SupabaseKey: "k"}); err != nil {
		t.Fatalf("StartupUpdateCheck() error: %v", err)
	}
	if hits != 0 {
		t.Errorf("RPC hits = %d, want 0 when offline", hits)
	}
}

func TestStartupUpdateCheck_HTTPFailureSkips(t *testing.T) {
	// The TCP probe "succeeds" but the Supabase HTTP endpoint is down.
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	fakeDial(t, false, "127.0.0.1:443")

	if err := StartupUpdateCheck(t.Context(), &config.Config{SupabaseURL: url, SupabaseKey: "k"}); err != nil {
		t.Fatalf("StartupUpdateCheck() error: %v", err)
	}
}

func TestStartupUpdateCheck_ChecksForUpdates(t *testing.T) {
	fakeDial(t, false, "127.0.0.1:443")
	var hits int64
	srv := countingRPCServer(t, http.StatusOK, &hits)

	if err := StartupUpdateCheck(t.Context(), &config.Config{SupabaseURL: srv.URL, SupabaseKey: "k"}); err != nil {
		t.Fatalf("StartupUpdateCheck() error: %v", err)
	}
	if hits != 1 {
		t.Errorf("RPC hits = %d, want 1", hits)
	}
}

func TestStartupUpdateCheck_UpdateErrorIsReturned(t *testing.T) {
	fakeDial(t, false, "127.0.0.1:443")
	var hits int64
	srv := countingRPCServer(t, http.StatusInternalServerError, &hits)

	// A cancelled context ends the retry loop at the first backoff instead of
	// sleeping through it.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := StartupUpdateCheck(ctx, &config.Config{SupabaseURL: srv.URL, SupabaseKey: "k"})
	if err == nil || !strings.Contains(err.Error(), "startup update check failed") {
		t.Errorf("StartupUpdateCheck() error = %v, want a wrapped update failure", err)
	}
}
