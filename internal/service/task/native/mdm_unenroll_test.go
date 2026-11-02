package native

import (
	"context"
	"slices"
	"strings"
	"testing"

	"sentinelgo/internal/taskstore"
)

func TestMDMUnenroll(t *testing.T) {
	h := Find("mdm-unenroll")
	if h == nil || Find("mdm_unenroll") != h {
		t.Fatal("mdm-unenroll not registered under both slugs")
	}
	SetMDMUnenroller(nil)
	if _, err := h.Run(context.Background(), nil, taskstore.Task{}); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Errorf("without a hook: %v", err)
	}
	SetMDMUnenroller(func(context.Context, map[string]interface{}) (string, error) { return "unenrolled: ok", nil })
	t.Cleanup(func() { SetMDMUnenroller(nil) })
	if note, err := h.Run(context.Background(), nil, taskstore.Task{}); err != nil || note != "unenrolled: ok" {
		t.Errorf("note %q err %v", note, err)
	}
	if pr, ok := h.(PostRunner); !ok || !slices.Equal(pr.PostRun(), []string{"sync-inventory"}) {
		t.Error("mdm-unenroll doesn't refresh the inventory afterwards")
	}
}
