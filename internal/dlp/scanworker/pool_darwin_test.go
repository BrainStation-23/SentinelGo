package scanworker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	case "probe": // checks the sandbox from inside a worker, then serves
		desc, err := sandbox()
		if err != nil {
			os.Exit(2)
		}
		if strings.Contains(desc, "pure-computation") {
			if f, err := os.Open("/etc/hosts"); err == nil {
				_ = f.Close()
				os.Exit(3)
			}
			if err := os.WriteFile(filepath.Join(os.TempDir(), "sentinelgo-probe"), []byte("x"), 0o600); err == nil {
				os.Exit(4)
			}
		}
		c, _, err := fileConn(os.NewFile(workerFD, "s"))
		if err != nil {
			os.Exit(5)
		}
		_ = serve(c, desc+",probed")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

const bundle = `{"schema_version":1,"version":"v1","enabled":true,
 "modules":{"files":{"enabled":true,"channels":{"file.removable":true},"scan_timeout_ms":5000}},
 "policies":[{"id":"p","name":"n","channels":["file.removable"],"action":"monitor",
   "detectors":[{"id":"custom.keywords","rule_id":"kw","min_count":1,"keywords":["TOPSECRET"]}]}]}`

func newPool(t *testing.T, mode string, workers int) *Pool {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p := NewPool(Options{Exe: exe, Args: []string{"-test.run=^$"}, Workers: workers, Env: []string{workerEnv + "=" + mode}})
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

// A real worker: it sandboxes itself at the strictest level that works here
// and scans a passed descriptor.
func TestDarwinPool_Scan(t *testing.T) {
	p := newPool(t, "serve", 1)
	f, size := tempFile(t, "hello TOPSECRET world")
	res := p.Scan(context.Background(), f, size, 10*time.Second)
	if res.Status != filescan.StatusScanned || len(res.Findings) != 1 || res.Findings[0].RuleID != "kw" || res.SHA256 == "" {
		t.Fatalf("result %+v (health %+v)", res, p.Health())
	}
	h := p.Health()
	if h.Workers != 1 || !strings.Contains(h.Sandbox, "rlimits") || h.Failures != 0 {
		t.Errorf("health %+v", h)
	}
	t.Logf("sandbox: %s", h.Sandbox) // pure-computation expected on current macOS
	if os.Geteuid() == 0 && !strings.Contains(h.Sandbox, ",user=") {
		t.Errorf("a root service's worker didn't drop to an unprivileged user: %q", h.Sandbox)
	}
}

// Inside a worker under pure-computation, opening or writing a path fails.
func TestDarwinSandbox_Probe(t *testing.T) {
	p := newPool(t, "probe", 1)
	f, size := tempFile(t, "TOPSECRET")
	res := p.Scan(context.Background(), f, size, 10*time.Second)
	if res.Status != filescan.StatusScanned {
		t.Fatalf("probe worker failed: %+v (health %+v)", res, p.Health())
	}
	if h := p.Health(); !strings.Contains(h.Sandbox, "probed") {
		t.Errorf("health %+v", h)
	}
}

func TestAccountIDs_Parse(t *testing.T) {
	prev := runDscl
	t.Cleanup(func() { runDscl = prev })
	runDscl = func(args ...string) ([]byte, error) {
		return []byte("PrimaryGroupID: -2\nUniqueID: 451\n"), nil
	}
	uid, gid, ok := accountIDs()
	if !ok || uid != 451 || gid != nobodyID {
		t.Errorf("uid %d gid %d ok %v", uid, gid, ok)
	}
	runDscl = func(args ...string) ([]byte, error) { return []byte("UniqueID: 0\nPrimaryGroupID: 0\n"), nil }
	if _, _, ok := accountIDs(); ok {
		t.Error("root accepted as the scan account")
	}
}

func TestCreateScanAccount(t *testing.T) {
	prev := runDscl
	t.Cleanup(func() { runDscl = prev })
	exists := false
	var created []string
	runDscl = func(args ...string) ([]byte, error) {
		switch args[1] {
		case "-read":
			if !exists {
				return nil, errors.New("no such record")
			}
			return []byte("UniqueID: 497\nPrimaryGroupID: -2\n"), nil
		case "-list":
			return []byte("root 0\n_www 70\n_taken 499\n_taken2 498\n"), nil
		case "-create":
			created = append(created, args[3]+"="+args[4])
			if args[3] == "Password" {
				exists = true
			}
		case "-delete":
			exists = false
		}
		return nil, nil
	}
	if err := createScanAccount(); err != nil {
		t.Fatal(err)
	}
	if len(created) != 7 || created[0] != "UniqueID=497" {
		t.Errorf("created %v", created)
	}
	if uid, gid, err := unprivilegedIDs(); err != nil || uid != 497 || gid != nobodyID {
		t.Errorf("ids %d %d %v", uid, gid, err)
	}
	created = nil
	if err := createScanAccount(); err != nil || len(created) != 0 {
		t.Errorf("created twice: %v %v", created, err)
	}
	if err := RemoveScanAccount(); err != nil || exists {
		t.Errorf("remove: %v exists=%v", err, exists)
	}
	if uid, _, _ := unprivilegedIDs(); uid != nobodyID {
		t.Errorf("without the account: uid %d", uid)
	}
	if err := RemoveScanAccount(); err != nil {
		t.Errorf("removing a missing account: %v", err)
	}
	// A create that fails is undone.
	runDscl = func(args ...string) ([]byte, error) {
		switch args[1] {
		case "-read":
			return nil, errors.New("no such record")
		case "-create":
			if args[3] == "UserShell" {
				return []byte("denied"), errors.New("exit 1")
			}
		case "-delete":
			created = append(created, "deleted")
		}
		return nil, nil
	}
	created = nil
	if err := createScanAccount(); err == nil || len(created) != 1 {
		t.Errorf("a failed create: %v %v", err, created)
	}
}
