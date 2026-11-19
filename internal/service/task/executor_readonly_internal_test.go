//go:build readonly

package task

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"sentinelgo/internal/taskstore"
)

// The read-only build refuses every script task and every removed native
// command without downloading or running anything (#547).
func TestReadOnly_RefusesScriptsAndRemovedCommands(t *testing.T) {
	var downloads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		downloads.Add(1)
		_, _ = w.Write([]byte("echo hi"))
	}))
	t.Cleanup(srv.Close)
	isolateTempDir(t)
	client := &fakeTaskClient{}
	s, _ := newExecutorFixture(t, client, srv.URL)
	body := "echo hi"
	tasks := []taskstore.Task{
		{ID: "script", Slug: "custom-script", CommandKind: taskstore.CommandKindSystem,
			Scripts: map[string]interface{}{runtime.GOOS: map[string]interface{}{"path": "x/run.sh"}}},
		{ID: "inline", Slug: "inline-script",
			Scripts: map[string]interface{}{runtime.GOOS: map[string]interface{}{"body": body, "filename": "run.sh"}}},
		{ID: "reboot", Slug: "device-reboot", CommandKind: taskstore.CommandKindNative},
		{ID: "admin", Slug: "local-admin-add", CommandKind: taskstore.CommandKindNative},
		// An older console sends device-reboot as a script: refused too.
		{ID: "reboot-script", Slug: "device-reboot",
			Scripts: map[string]interface{}{runtime.GOOS: map[string]interface{}{"path": "x/reboot.sh"}}},
	}
	seedTasks(t, s.pollingSvc, tasks...)
	s.ExecutePendingTasks(context.Background())

	u := client.recorded()
	if len(u) != len(tasks) {
		t.Fatalf("reported %d results, want %d: %+v", len(u), len(tasks), u)
	}
	for _, r := range u {
		if r.status != "failed" || !strings.Contains(r.note, "not available in this read-only build") {
			t.Errorf("%+v, want failed: not available in this read-only build", r)
		}
	}
	if downloads.Load() != 0 {
		t.Errorf("downloaded %d scripts", downloads.Load())
	}
}
