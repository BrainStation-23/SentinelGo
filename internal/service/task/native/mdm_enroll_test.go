package native

import (
	"context"
	"slices"
	"strings"
	"testing"

	"sentinelgo/internal/taskstore"
)

func TestMDMEnroll(t *testing.T) {
	h := Find("mdm-enroll")
	if h == nil || Find("mdm_enroll") != h {
		t.Fatal("mdm-enroll not registered under both slugs")
	}
	SetMDMEnroller(nil)
	if _, err := h.Run(context.Background(), nil, taskstore.Task{}); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Errorf("without a hook: %v", err)
	}

	var got map[string]interface{}
	SetMDMEnroller(func(_ context.Context, p map[string]interface{}) (string, error) { got = p; return "enrolled: ok", nil })
	t.Cleanup(func() { SetMDMEnroller(nil) })
	note, err := h.Run(context.Background(), nil, taskstore.Task{Payload: map[string]interface{}{"method": "profile"}})
	if err != nil || note != "enrolled: ok" || got["method"] != "profile" {
		t.Errorf("note %q err %v payload %v", note, err, got)
	}
	if pr, ok := h.(PostRunner); !ok || !slices.Equal(pr.PostRun(), []string{"sync-inventory"}) {
		t.Error("mdm-enroll doesn't refresh the inventory afterwards")
	}
}
