package native

import (
	"context"
	"errors"
	"strings"
	"testing"

	"sentinelgo/internal/taskstore"
)

func TestDLPSyncPolicy(t *testing.T) {
	h := Find("dlp_sync_policy")
	if h == nil {
		t.Fatal("dlp_sync_policy not registered")
	}
	t.Cleanup(func() { SetDLPPolicySync(nil) })

	SetDLPPolicySync(nil)
	if _, err := h.Run(context.Background(), nil, taskstore.Task{}); !errors.Is(err, errDLPOff) {
		t.Errorf("without DLP: err = %v", err)
	}

	SetDLPPolicySync(func(context.Context) (string, string, error) { return "sha256:v9", "enforcing", nil })
	note, err := h.Run(context.Background(), nil, taskstore.Task{})
	if err != nil || !strings.Contains(note, "sha256:v9") || !strings.Contains(note, "enforcing") {
		t.Errorf("note = %q, err = %v", note, err)
	}

	SetDLPPolicySync(func(context.Context) (string, string, error) { return "", "", errors.New("offline") })
	if _, err := h.Run(context.Background(), nil, taskstore.Task{}); err == nil || !strings.Contains(err.Error(), "offline") {
		t.Errorf("failed poll: err = %v", err)
	}
}
