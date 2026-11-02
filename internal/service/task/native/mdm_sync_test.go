package native

import (
	"context"
	"strings"
	"testing"

	"sentinelgo/internal/taskstore"
)

func TestMDMSync(t *testing.T) {
	h := Find("mdm-sync")
	if h == nil || Find("mdm_sync") != h {
		t.Fatal("mdm-sync not registered under both slugs")
	}
	SetMDMSyncer(nil)
	if _, err := h.Run(context.Background(), nil, taskstore.Task{}); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Errorf("without a hook: %v", err)
	}
	SetMDMSyncer(func(_ context.Context, p map[string]interface{}) (string, error) { return "synced: ok", nil })
	t.Cleanup(func() { SetMDMSyncer(nil) })
	if note, err := h.Run(context.Background(), nil, taskstore.Task{}); err != nil || note != "synced: ok" {
		t.Errorf("note %q err %v", note, err)
	}
}
