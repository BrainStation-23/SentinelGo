//go:build !windows

package task

import (
	"context"
	"runtime"
	"testing"

	"sentinelgo/internal/taskstore"
)

// TestInventorySync_NotWhenInterpreterMissing: a system .ps1 on a device
// without pwsh fails before any process starts, so nothing changed and no
// inventory is sent.
func TestInventorySync_NotWhenInterpreterMissing(t *testing.T) {
	stubInterpreters(t)
	tk := taskstore.Task{
		ID: "t1", Slug: "usb-storage-disable", CommandKind: taskstore.CommandKindSystem,
		Scripts: map[string]interface{}{runtime.GOOS: map[string]interface{}{"filename": "run.ps1", "body": "Write-Output hi\n"}},
	}
	_, client, rec := runBatch(t, context.Background(), nil, tk)
	if u := client.recorded(); len(u) != 1 || u[0].status != "failed" {
		t.Fatalf("reported %+v, want one failed update", u)
	}
	if rec.calls() != 0 {
		t.Errorf("syncs = %d, want 0 when the interpreter is missing", rec.calls())
	}
}
