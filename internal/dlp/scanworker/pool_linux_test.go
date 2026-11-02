package scanworker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"sentinelgo/internal/dlp/filescan"
)

// The test binary doubles as the worker: with this variable set, TestMain
// serves on fd 3 (sandbox included) instead of running tests.
const workerEnv = "SENTINELGO_SCANWORKER_TEST"

func TestMain(m *testing.M) {
	switch os.Getenv(workerEnv) {
	case "serve":
		if err := Serve(); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	case "hang": // a worker that says hello, then never answers
		_ = os.Setenv(workerEnv, "")
		if _, err := sandbox(); err != nil {
			os.Exit(1)
		}
		f := os.NewFile(workerFD, "s")
		c, _, _ := fileConn(f)
		_ = c.writeMsg(message{Type: typeReady, Sandbox: "test"}, -1)
		time.Sleep(time.Hour)
	case "probe": // checks the sandbox from inside a worker
		if _, err := sandbox(); err != nil {
			os.Exit(2)
		}
		if _, err := os.Open("/etc/hostname"); err == nil && landlockAvailable() {
			os.Exit(3) // Landlock should have stopped this
		}
		if err := os.WriteFile(filepath.Join(os.TempDir(), "x"), []byte("x"), 0o600); err == nil {
			os.Exit(4)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func landlockAvailable() bool {
	_, err := landlock()
	return err == nil
}

const bundle = `{"schema_version":1,"version":"v1","enabled":true,
 "modules":{"files":{"enabled":true,"channels":{"file.removable":true},"scan_timeout_ms":5000}},
 "policies":[{"id":"p","name":"n","channels":["file.removable"],"action":"monitor",
   "detectors":[{"id":"custom.keywords","rule_id":"kw","min_count":1,"keywords":["TOPSECRET"]}]}]}`

func newPool(t *testing.T, mode string, workers int) *Pool {
	t.Helper()
	p := NewPool(Options{Exe: testExe(t), Args: []string{"-test.run=^$"}, Workers: workers, Env: []string{workerEnv + "=" + mode}})
	p.SetPolicy([]byte(bundle))
	t.Cleanup(p.Stop)
	return p
}

func tempFile(t *testing.T, content string) (*os.File, int64) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f.txt")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f, int64(len(content))
}

func TestPool_Scan(t *testing.T) {
	p := newPool(t, "serve", 2)
	f, size := tempFile(t, "hello TOPSECRET world")
	res := p.Scan(context.Background(), f, size, 5*time.Second)
	if res.Status != filescan.StatusScanned || len(res.Findings) != 1 || res.Findings[0].RuleID != "kw" || res.SHA256 == "" {
		t.Fatalf("result %+v", res)
	}
	h := p.Health()
	if h.Workers != 1 || !strings.Contains(h.Sandbox, "no_new_privs") || h.Failures != 0 {
		t.Errorf("health %+v", h)
	}
	if os.Geteuid() == 0 && !strings.Contains(h.Sandbox, ",user=") {
		t.Errorf("a root service's worker didn't drop to an unprivileged user: %q", h.Sandbox)
	}
	// A new policy reaches the worker before its next scan.
	p.SetPolicy([]byte(strings.Replace(bundle, "TOPSECRET", "hello", 1)))
	if res := p.Scan(context.Background(), f, size, 5*time.Second); len(res.Findings) != 1 || res.Findings[0].Masked == "" || res.Findings[0].Count != 1 {
		t.Errorf("after policy change: %+v", res)
	}
}

func TestPool_Concurrent(t *testing.T) {
	p := newPool(t, "serve", 2)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f, size := tempFile(t, "TOPSECRET")
			if res := p.Scan(context.Background(), f, size, 5*time.Second); res.Status != filescan.StatusScanned || len(res.Findings) != 1 {
				t.Errorf("result %+v", res)
			}
		}()
	}
	wg.Wait()
	if h := p.Health(); h.Workers > 2 {
		t.Errorf("%d workers for a pool of 2", h.Workers)
	}
}

// A worker that doesn't answer is killed at the deadline; the scan is a
// timeout and the stuck process is gone.
func TestPool_StuckWorker(t *testing.T) {
	p := newPool(t, "hang", 1)
	f, size := tempFile(t, "TOPSECRET")
	start := time.Now()
	res := p.Scan(context.Background(), f, size, 100*time.Millisecond)
	if res.Status != filescan.StatusTimeout {
		t.Fatalf("status %q", res.Status)
	}
	if d := time.Since(start); d > scanGrace+3*time.Second {
		t.Errorf("took %v", d)
	}
	if h := p.Health(); h.Workers != 0 {
		t.Errorf("stuck worker still counted: %+v", h)
	}
}

// Workers that can't start count as failures; enough of them disable the pool
// instead of restarting forever.
func TestPool_CrashLoop(t *testing.T) {
	p := NewPool(Options{Exe: "/nonexistent/sentinelgo", Workers: 1})
	p.SetPolicy([]byte(bundle))
	defer p.Stop()
	f, size := tempFile(t, "x")
	for i := 0; i < crashLimit; i++ {
		if res := p.Scan(context.Background(), f, size, time.Second); res.Status != filescan.Unscannable(ReasonWorkerFailed) {
			t.Fatalf("status %q", res.Status)
		}
	}
	if h := p.Health(); !h.Disabled || h.Failures != crashLimit {
		t.Errorf("health %+v", h)
	}
}

func TestPool_Stop(t *testing.T) {
	p := newPool(t, "serve", 1)
	f, size := tempFile(t, "TOPSECRET")
	p.Scan(context.Background(), f, size, 5*time.Second)
	p.Stop()
	if res := p.Scan(context.Background(), f, size, 5*time.Second); res.Status != filescan.Unscannable(ReasonWorkerFailed) {
		t.Errorf("after stop: %q", res.Status)
	}
	if h := p.Health(); h.Workers != 0 {
		t.Errorf("workers after stop: %+v", h)
	}
}

// The sandbox really applies: a worker can't open files by path (with
// Landlock) or write files.
func TestSandbox_Probe(t *testing.T) {
	p := NewPool(Options{Exe: testExe(t), Args: []string{"-test.run=^$"}, Workers: 1, Env: []string{workerEnv + "=probe"}})
	c, child, err := socketPair()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.c.Close() }()
	cmd, err := p.command(child)
	if err != nil {
		t.Fatal(err)
	}
	err = cmd.Run()
	if errors.Is(err, syscall.EPERM) {
		// No network namespace allowed here; the pool falls back the same way.
		if cmd, err = p.command(child); err != nil {
			t.Fatal(err)
		}
		cmd.SysProcAttr.Cloneflags = 0
		err = cmd.Run()
	}
	if err != nil {
		t.Fatalf("probe worker: %v (exit 2: sandbox failed, 3: opened a file by path, 4: wrote a file)", err)
	}
}

// Cancelling the context ends a scan at once, without waiting for the
// deadline.
func TestPool_CancelledScan(t *testing.T) {
	p := newPool(t, "hang", 1)
	f, size := tempFile(t, "TOPSECRET")
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	res := p.Scan(ctx, f, size, time.Minute)
	if res.Status != filescan.StatusTimeout || time.Since(start) > 3*time.Second {
		t.Errorf("status %q after %v", res.Status, time.Since(start))
	}
}
