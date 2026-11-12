package rpcutil

import (
	"encoding/json"
	"testing"

	"sentinelgo/internal/remoteconfig"
)

// TestObserveConfig: the config member of an enqueue reply reaches the
// remoteconfig handler (#466); replies without one, or not JSON, don't.
func TestObserveConfig(t *testing.T) {
	var got []string
	remoteconfig.SetHandler(func(raw json.RawMessage) { got = append(got, string(raw)) })
	t.Cleanup(func() { remoteconfig.SetHandler(nil) })

	ObserveConfigIn([]byte(`{"success": true, "config": {"version": 3}}`))
	ObserveConfigIn([]byte(`{"success": true}`))
	ObserveConfigIn([]byte(`not json`))

	var resp EnqueueResponse
	if err := json.Unmarshal([]byte(`{"enqueued": true, "config": {"version": 4}}`), &resp); err != nil {
		t.Fatal(err)
	}
	resp.ObserveConfig()

	if len(got) != 2 || got[0] != `{"version": 3}` || got[1] != `{"version": 4}` {
		t.Fatalf("handler got %q, want the two config members", got)
	}
}
