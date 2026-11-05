package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/localadmin"
)

type fakeExpirer struct {
	state string
	err   error
	ids   []string
}

func (f *fakeExpirer) Expire(_ context.Context, id string) (string, error) {
	f.ids = append(f.ids, id)
	return f.state, f.err
}

func TestRunLocalAdmin(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.json")
	fe := &fakeExpirer{state: localadmin.GrantRemoved}
	origM, origS := localAdminManager, cliSleep
	t.Cleanup(func() { localAdminManager, cliSleep = origM, origS })
	var gotDir string
	localAdminManager = func(d string) (localAdminExpirer, error) { gotDir = d; return fe, nil }
	cliSleep = func(context.Context, time.Duration) {}

	var out, errb bytes.Buffer
	if code := RunLocalAdmin([]string{"expire", "g-1", "-config", cfg}, &out, &errb); code != 0 || gotDir != dir || fe.ids[0] != "g-1" {
		t.Fatalf("code %d dir %q ids %v err %s", code, gotDir, fe.ids, errb.String())
	}
	if !strings.Contains(out.String(), "g-1: removed") {
		t.Fatal(out.String())
	}

	fe.state = localadmin.GrantFailed
	if code := RunLocalAdmin([]string{"expire", "g-1", "-config", cfg}, &out, &errb); code != 1 {
		t.Fatalf("failed removal exit %d", code)
	}
	fe.err = errors.New("no grant")
	if code := RunLocalAdmin([]string{"expire", "g-1", "-config", cfg}, &out, &errb); code != 1 {
		t.Fatalf("error exit %d", code)
	}
	for _, args := range [][]string{nil, {"expire"}, {"expire", "../x"}, {"nope"}} {
		if code := RunLocalAdmin(args, &out, &errb); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	out.Reset()
	if code := RunLocalAdmin([]string{"status", "-config", cfg}, &out, &errb); code != 0 || strings.TrimSpace(out.String()) != "null" {
		t.Fatalf("status %d %q", code, out.String())
	}
}
