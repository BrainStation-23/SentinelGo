//go:build linux || windows || darwin

package scanworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/yara"
)

const (
	// A marker, not EICAR: antivirus quarantines EICAR files on test machines.
	yaraEICAR = "SENTINELGO-YARA-TEST-MARKER-7f3a"
	rsEICAR   = "11111111-1111-4111-8111-111111111111"
	rsSlow    = "22222222-2222-4222-8222-222222222222"
	rsBad     = "33333333-3333-4333-8333-333333333333"
)

var yaraTestRules = []yara.RuleSource{
	{ID: rsEICAR, Revision: 2, Source: []byte(`import "pe"
rule needs_pe { condition: pe.is_dll() }
rule eicar : test { strings: $sig = "YARA-TEST-MARKER" condition: $sig and filename == "eicar.com" }`)},
	{ID: rsSlow, Revision: 1, Source: []byte(`rule slow { strings: $a = /(a+)+b/ condition: $a }`)},
}

func yaraFile(t *testing.T, name, content string) (*os.File, int64) {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p) // #nosec G304 -- a test file
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f, int64(len(content))
}

func scanYARA(t *testing.T, p *Pool, r *YARARules, name, content string, ids []string, timeout time.Duration) YARAResult {
	t.Helper()
	f, size := yaraFile(t, name, content)
	return p.ScanYARA(context.Background(), r, YARAScan{File: f, Size: size, Path: filepath.Join("C:", "x", name), RulesetIDs: ids, Timeout: timeout})
}

// A real, sandboxed worker compiles the rules itself and scans a file it is
// handed; the result has identifiers, the hash and the size, never content.
func TestYARAPool_CompileAndScan(t *testing.T) {
	p := yaraTestPool(t)
	r := NewYARARules(yaraTestRules)
	res, err := p.CompileYARA(context.Background(), r)
	if err != nil {
		t.Fatalf("compile: %v (health %+v)", err, p.Health())
	}
	if len(res) != 2 || res[0].Rules != 1 || len(res[0].Skipped) != 1 || res[0].Skipped[0].Reason != "unsupported_module:pe" || res[1].Rules != 1 {
		t.Fatalf("compiled %+v", res)
	}
	content := "x " + yaraEICAR
	got := scanYARA(t, p, r, "eicar.com", content, []string{rsEICAR}, 0)
	sum := sha256.Sum256([]byte(content))
	if got.Status != YARAScanned || len(got.Matches) != 1 || got.Matches[0].Rule != "eicar" ||
		got.Matches[0].Namespace != rsEICAR || got.SHA256 != hex.EncodeToString(sum[:]) || got.Size != int64(len(content)) {
		t.Fatalf("scan %+v", got)
	}
	if strings.Contains(strings.Join(got.Matches[0].StringIDs, ","), "MARKER") {
		t.Errorf("string ids carry content: %v", got.Matches[0].StringIDs)
	}
	// The filename external is the path's base name.
	if got := scanYARA(t, p, r, "other.txt", content, []string{rsEICAR}, 0); got.Status != YARAScanned || len(got.Matches) != 0 || got.SHA256 == "" {
		t.Errorf("other name: %+v", got)
	}
	// Only the rulesets asked for run.
	if got := scanYARA(t, p, r, "eicar.com", content, []string{rsSlow}, 0); got.Status != YARAScanned || len(got.Matches) != 0 {
		t.Errorf("filtered: %+v", got)
	}
	if got := scanYARA(t, p, r, "eicar.com", content, []string{"44444444-4444-4444-8444-444444444444"}, 0); got.Status != YARANoRules {
		t.Errorf("unknown ruleset: %+v", got)
	}
	// A new set reaches the worker before its next scan; a ruleset that
	// doesn't compile at all is reported, the others still scan.
	r2 := NewYARARules([]yara.RuleSource{yaraTestRules[0], {ID: rsBad, Revision: 1, Source: []byte(`include "x.yar"`)}})
	if got := scanYARA(t, p, r2, "eicar.com", content, nil, 0); got.Status != YARAScanned || len(got.Matches) != 1 {
		t.Errorf("new set: %+v", got)
	}
	res, err = p.CompileYARA(context.Background(), r2)
	if err != nil || len(res) != 2 || res[1].Error == "" || res[1].Rules != 0 {
		t.Errorf("bad ruleset: %+v %v", res, err)
	}
}

// A pathological regex hits the per-file timeout; the file is reported as
// a timeout and the next file scans.
func TestYARAPool_Timeout(t *testing.T) {
	p := yaraTestPool(t)
	r := NewYARARules(yaraTestRules)
	start := time.Now()
	got := scanYARA(t, p, r, "a.txt", strings.Repeat("a", 1<<20), nil, 500*time.Millisecond)
	if got.Status != YARATimeout {
		t.Fatalf("slow file: %+v", got)
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("timeout took %v", d)
	}
	if got := scanYARA(t, p, r, "eicar.com", yaraEICAR, []string{rsEICAR}, 5*time.Second); got.Status != YARAScanned || len(got.Matches) != 1 {
		t.Fatalf("next file: %+v", got)
	}
	if h := p.Health(); h.Disabled || h.Failures != 0 {
		t.Errorf("a timeout counted as a worker failure: %+v", h)
	}
}

// Killing the worker mid-scan fails that file as worker_failed; the next
// file gets a new worker.
func TestYARAPool_WorkerKilled(t *testing.T) {
	p := yaraTestPool(t)
	r := NewYARARules(yaraTestRules)
	if _, err := p.CompileYARA(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(time.Second)
		p.mu.Lock()
		var victims []*worker
		for w := range p.all {
			victims = append(victims, w)
		}
		p.mu.Unlock()
		for _, w := range victims {
			w.kill()
		}
	}()
	if got := scanYARA(t, p, r, "a.txt", strings.Repeat("a", 1<<20), []string{rsSlow}, 30*time.Second); got.Status != YARAWorkerFailed {
		t.Fatalf("killed worker: %+v", got)
	}
	if got := scanYARA(t, p, r, "eicar.com", yaraEICAR, []string{rsEICAR}, 5*time.Second); got.Status != YARAScanned || len(got.Matches) != 1 {
		t.Fatalf("next file: %+v (health %+v)", got, p.Health())
	}
}
