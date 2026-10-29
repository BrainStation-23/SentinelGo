package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sentinelgo/internal/config"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
	"sentinelgo/internal/store"
)

const testBundle = `{"schema_version":1,"version":"sha256:test","enabled":true,"evidence_mode":"masked",
 "modules":{"clipboard":{"enabled":true}},
 "policies":[
  {"id":"p1","name":"Block cards","severity":"high","channels":["clipboard"],"action":"block","match":"any",
   "detectors":[{"id":"pii.credit_card","rule_id":"r1","min_count":1}]},
  {"id":"p2","name":"Falcon","severity":"low","channels":["clipboard"],"action":"monitor","match":"any",
   "detectors":[{"id":"custom.regex","rule_id":"r2","pattern":"falcon-\\d+"},{"id":"custom.regex","rule_id":"r-bad","pattern":"("}]}
 ]}`

// dlpTestConfig points loadDefaultConfig at a temp dir holding a cached
// bundle (and, with events, a queue).
func dlpTestConfig(t *testing.T, cache bool, queued int) {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{Path: filepath.Join(dir, "config.json"), DLPEnabled: true}
	prev := loadDefaultConfig
	loadDefaultConfig = func() (*config.Config, error) { return cfg, nil }
	t.Cleanup(func() { loadDefaultConfig = prev })
	if cache {
		b, err := policy.Decode([]byte(testBundle))
		if err != nil {
			t.Fatal(err)
		}
		if err := policy.NewCache(filepath.Join(dir, policy.CacheFileName)).Save(b); err != nil {
			t.Fatal(err)
		}
	}
	if queued > 0 {
		q, err := store.NewDLPEventStore(filepath.Join(dir, store.DLPEventsDBName))
		if err != nil {
			t.Fatal(err)
		}
		for i := range queued {
			if _, err := q.Add(events.Event{EventID: events.NewID(), ContentSHA256: string(rune('a' + i)), PolicyID: "p1"}); err != nil {
				t.Fatal(err)
			}
		}
		_ = q.Close()
	}
}

func runDLP(t *testing.T, stdin string, args ...string) (code int, out, errOut string) {
	t.Helper()
	var o, e bytes.Buffer
	code = RunDLP(args, strings.NewReader(stdin), &o, &e)
	return code, o.String(), e.String()
}

func TestDLPStatus_Offline(t *testing.T) {
	dlpTestConfig(t, true, 2)
	code, out, _ := runDLP(t, "", "status")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"sha256:test", "Block cards [block, high]", "rule r-bad skipped", "2 events"} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "falcon-") {
		t.Error("status prints a policy pattern")
	}

	code, out, _ = runDLP(t, "", "status", "-json")
	var st DLPStatus
	if code != 0 || json.Unmarshal([]byte(out), &st) != nil || st.Policy == nil || len(st.Policy.Policies) != 2 || st.Queue.Events != 2 {
		t.Errorf("json status = %s", out)
	}
}

func TestDLPStatus_NoPolicy(t *testing.T) {
	dlpTestConfig(t, false, 0)
	_, out, _ := runDLP(t, "", "status")
	if !strings.Contains(out, "none cached") {
		t.Errorf("status = %s", out)
	}
}

// dlp test prints masked findings only, never the raw match.
func TestDLPTest_MaskedOnly(t *testing.T) {
	dlpTestConfig(t, true, 0)
	code, out, _ := runDLP(t, "pay 4111 1111 1111 1111 for falcon-42", "test")
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{`Matched "Block cards"`, `Matched "Falcon"`, "Policy outcome: BLOCK", "4111***********1111"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, raw := range []string{"4111 1111 1111 1111", "falcon-42"} {
		if strings.Contains(out, raw) {
			t.Errorf("output contains the raw match %q:\n%s", raw, out)
		}
	}

	_, out, _ = runDLP(t, "hello world", "test")
	if !strings.Contains(out, "No policy matched") {
		t.Errorf("clean input: %s", out)
	}
}

func TestDLPTest_NoPolicyAndUsage(t *testing.T) {
	dlpTestConfig(t, false, 0)
	if code, _, e := runDLP(t, "x", "test"); code != 1 || !strings.Contains(e, "No policy cached") {
		t.Errorf("exit %d, stderr %q", code, e)
	}
	if code, _, _ := runDLP(t, ""); code != 2 {
		t.Errorf("no subcommand: exit %d, want 2", code)
	}
	if code, _, _ := runDLP(t, "", "bogus"); code != 2 {
		t.Errorf("unknown subcommand: exit %d, want 2", code)
	}
	if code, _, _ := runDLP(t, "", "test", "-file", filepath.Join(t.TempDir(), "missing")); code != 1 {
		t.Errorf("missing file: exit %d, want 1", code)
	}
}

// dlp test says when nothing would be enforced, and what wasn't scanned.
func TestDLPTest_OffAndTruncated(t *testing.T) {
	dlpTestConfig(t, true, 0)
	cfg, _ := loadDefaultConfig()
	cfg.DLPEnabled = false
	_, out, _ := runDLP(t, "4111111111111111", "test")
	if !strings.Contains(out, "nothing is enforced: DLP is off on this device") {
		t.Errorf("local switch off not reported:\n%s", out)
	}

	cfg.DLPEnabled = true
	big := strings.Repeat("x", (1<<20)+10) + " 4111111111111111"
	_, out, _ = runDLP(t, big, "test")
	if !strings.Contains(out, "only the first 1048576 bytes are scanned") || strings.Contains(out, "Matched") {
		t.Errorf("truncation not reported:\n%s", out[:min(len(out), 400)])
	}
}

// -config inspects a non-default install.
func TestDLP_ConfigFlag(t *testing.T) {
	dlpTestConfig(t, true, 0)
	cfg, _ := loadDefaultConfig()
	prev := loadDefaultConfig
	loadDefaultConfig = func() (*config.Config, error) { t.Fatal("default config used despite -config"); return nil, nil }
	t.Cleanup(func() { loadDefaultConfig = prev })
	if err := os.WriteFile(cfg.Path, []byte(`{"dlp_enabled": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runDLP(t, "", "status", "-config", cfg.Path)
	if code != 0 || !strings.Contains(out, "sha256:test") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}
