package remoteconfig

import (
	"encoding/json"
	"testing"
)

func TestObserve(t *testing.T) {
	t.Cleanup(func() { SetHandler(nil) })

	// No handler: nothing happens (CLI commands).
	Observe(json.RawMessage(`{"version": 1}`))

	var got []string
	SetHandler(func(raw json.RawMessage) { got = append(got, string(raw)) })

	Observe(nil)
	Observe(json.RawMessage(" null "))
	Observe(json.RawMessage(`{"version": 2}`))

	if len(got) != 1 || got[0] != `{"version": 2}` {
		t.Fatalf("handler got %q, want only the object", got)
	}

	SetHandler(nil)
	Observe(json.RawMessage(`{"version": 3}`))
	if len(got) != 1 {
		t.Fatalf("handler called after unregistering")
	}
}
