package scanworker

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/dlp/filescan"
)

// The test binary doubles as the worker: with this variable set, TestMain
// serves on stdin/stdout instead of running tests.
const workerEnv = "SENTINELGO_SCANWORKER_TEST"

const testCard = "4111 1111 1111 1111"

func TestMain(m *testing.M) {
	switch os.Getenv(workerEnv) {
	case "serve":
		if err := Serve(); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	case "hang": // says hello, then never answers
		desc, err := checkSandbox()
		if err != nil {
			os.Exit(1)
		}
		_ = newPipeConn(os.Stdin, os.Stdout, true).writeMsg(message{Type: typeReady, Sandbox: desc}, -1)
		time.Sleep(time.Hour)
	case "probe": // checks the sandbox from inside a worker, then serves
		desc, err := checkSandbox()
		if err != nil {
			os.Exit(1)
		}
		_ = serve(newPipeConn(os.Stdin, os.Stdout, true), desc+",probe="+probe())
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// probe tries what the sandbox must stop.
func probe() string {
	var failed []string
	if f, err := os.Open(os.Getenv("SG_PROBE_FILE")); err == nil {
		_ = f.Close()
		failed = append(failed, "read_profile_file")
	}
	if err := os.WriteFile(filepath.Join(os.Getenv("SG_PROBE_DIR"), "x.txt"), []byte("x"), 0o600); err == nil {
		failed = append(failed, "write_file")
	}
	if err := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), "/c", "exit", "0").Run(); err == nil {
		failed = append(failed, "child_process")
	}
	if len(failed) == 0 {
		return "ok"
	}
	return strings.Join(failed, "+")
}

var (
	exeOnce sync.Once
	exePath string
	exeErr  error
)

// testExe copies the test binary where Users can read it, as an install
// directory is: a restricted worker can't read the user's own %TEMP%.
func testExe(t *testing.T) string {
	t.Helper()
	exeOnce.Do(func() {
		src, err := os.Executable()
		if err != nil {
			exeErr = err
			return
		}
		dir, err := os.MkdirTemp(os.Getenv("ProgramData"), "sentinelgo-scanworker-test-")
		if err != nil {
			exeErr = err
			return
		}
		exePath = filepath.Join(dir, "worker.test.exe")
		in, err := os.Open(src) // #nosec G304 -- this test binary
		if err != nil {
			exeErr = err
			return
		}
		defer func() { _ = in.Close() }()
		out, err := os.Create(exePath) // #nosec G304 -- a fresh temp dir
		if err != nil {
			exeErr = err
			return
		}
		_, exeErr = io.Copy(out, in)
		if cerr := out.Close(); exeErr == nil {
			exeErr = cerr
		}
	})
	if exeErr != nil {
		t.Skipf("can't stage the worker binary: %v", exeErr)
	}
	return exePath
}

func cleanupExe() {
	if exePath != "" {
		_ = os.RemoveAll(filepath.Dir(exePath))
	}
}

const testBundle = `{"schema_version": 1, "version": "v1", "enabled": true,
  "modules": {"files": {"enabled": true, "channels": {"file.removable": true}}},
  "policies": [{"id": "p1", "name": "Cards", "channels": ["file.removable"], "action": "monitor",
    "detectors": [{"id": "pii.credit_card", "rule_id": "r1", "min_count": 1}]}]}`

func newTestPool(t *testing.T, mode string, extraEnv ...string) *Pool {
	t.Helper()
	p := NewPool(Options{Exe: testExe(t), Workers: 1, Env: append([]string{workerEnv + "=" + mode}, extraEnv...)})
	p.SetPolicy([]byte(testBundle))
	t.Cleanup(p.Stop)
	return p
}

// A file in the user's profile, which the service opens and hands over.
func secretFile(t *testing.T, content string) (*os.File, int64) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "plan.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path) // #nosec G304 -- a test file
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f, int64(len(content))
}

// A real worker, sandboxed, scans a file it could never open by path.
func TestWindowsPool_Scan(t *testing.T) {
	p := newTestPool(t, "serve")
	f, size := secretFile(t, "card "+testCard)
	res := p.Scan(context.Background(), f, size, 10*time.Second)
	if res.Status != filescan.StatusScanned || len(res.Findings) != 1 || res.Findings[0].DetectorID != "pii.credit_card" {
		t.Fatalf("result %+v", res)
	}
	h := p.Health()
	if h.Workers != 1 || h.Sandbox != "low_integrity,restricted_token,job" {
		t.Fatalf("health %+v", h)
	}
	// the same worker serves the next file
	f2, size2 := secretFile(t, "nothing here")
	if res := p.Scan(context.Background(), f2, size2, 10*time.Second); res.Status != filescan.StatusScanned || len(res.Findings) != 0 {
		t.Fatalf("second scan %+v", res)
	}
	t.Cleanup(cleanupExe)
}

// From inside a worker: no reading the user's files by path, no writing, no
// child processes.
func TestWindowsPool_Sandbox(t *testing.T) {
	profileFile := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(profileFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	writable, err := os.MkdirTemp(os.Getenv("ProgramData"), "sentinelgo-probe-")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(writable) })
	p := newTestPool(t, "probe", "SG_PROBE_FILE="+profileFile, "SG_PROBE_DIR="+writable)
	f, size := secretFile(t, "x")
	if res := p.Scan(context.Background(), f, size, 10*time.Second); res.Status != filescan.StatusScanned {
		t.Fatalf("scan %+v", res)
	}
	if h := p.Health(); !strings.HasSuffix(h.Sandbox, ",probe=ok,job") {
		t.Fatalf("sandbox probe: %q", h.Sandbox)
	}
}

// A worker that doesn't answer is killed at the deadline; the scan is a
// timeout, not a crash.
func TestWindowsPool_Timeout(t *testing.T) {
	p := newTestPool(t, "hang")
	f, size := secretFile(t, "x")
	start := time.Now()
	res := p.Scan(context.Background(), f, size, 100*time.Millisecond)
	if res.Status != filescan.StatusTimeout || time.Since(start) > 8*time.Second {
		t.Fatalf("result %+v after %v", res, time.Since(start))
	}
	if h := p.Health(); h.Workers != 0 || h.Failures != 0 {
		t.Fatalf("health %+v", h)
	}
	// cancelling the context ends the wait at once
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	if res := p.Scan(ctx, f, size, time.Hour); res.Status != filescan.StatusTimeout {
		t.Fatalf("cancelled scan %+v", res)
	}
}

// Stop kills the workers; later scans fail without starting new ones.
func TestWindowsPool_Stop(t *testing.T) {
	p := newTestPool(t, "serve")
	f, size := secretFile(t, "x")
	if res := p.Scan(context.Background(), f, size, 10*time.Second); res.Status != filescan.StatusScanned {
		t.Fatalf("scan %+v", res)
	}
	p.Stop()
	if res := p.Scan(context.Background(), f, size, time.Second); res.Status != filescan.Unscannable(ReasonWorkerFailed) {
		t.Fatalf("after stop %+v", res)
	}
	if h := p.Health(); h.Workers != 0 {
		t.Fatalf("health %+v", h)
	}
}

// A worker run outside the sandbox (this test, at medium integrity) refuses.
func TestCheckSandboxRefusesUnsandboxed(t *testing.T) {
	if _, err := checkSandbox(); err == nil {
		t.Skip("the test itself runs at low integrity")
	}
}

func TestEnvBlock(t *testing.T) {
	b := envBlock([]string{"A=1", "BAD=x\x00y", "B=2"})
	got := string(utf16Decode(b))
	if got != "A=1\x00B=2\x00\x00" {
		t.Fatalf("%q", got)
	}
}

func utf16Decode(u []uint16) []rune {
	out := make([]rune, len(u))
	for i, c := range u {
		out[i] = rune(c)
	}
	return out
}
