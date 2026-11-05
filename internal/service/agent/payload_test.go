package agent

import (
	"encoding/json"
	"testing"

	"sentinelgo/internal/osinfo/shared"
)

// inventoryListKeys are the payload keys filled from collector slices (#387).
var inventoryListKeys = []string{
	"disks", "gpus", "network_adapters", "peripherals",
	"audio_devices", "printers", "display", "local_users",
}

func marshalPayload(t *testing.T, si *shared.SystemInfo) map[string]json.RawMessage {
	t.Helper()
	b, err := json.Marshal(buildPayload(si))
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return m
}

// A collector that failed leaves a nil slice: the key must be left out,
// never sent as null, so the server keeps its last good value.
func TestBuildPayload_NilListsAreOmitted(t *testing.T) {
	m := marshalPayload(t, &shared.SystemInfo{Hostname: "h"})
	for _, k := range inventoryListKeys {
		if v, ok := m[k]; ok {
			t.Errorf("key %q sent as %s, want it left out", k, v)
		}
	}
}

// A collector that ran and found nothing still reports [].
func TestBuildPayload_EmptyListsAreSent(t *testing.T) {
	m := marshalPayload(t, &shared.SystemInfo{
		Hostname:        "h",
		Disks:           []shared.DiskDevice{},
		GPUs:            []shared.GPU{},
		NetworkAdapters: []shared.NetAdapter{},
		Peripherals:     []shared.PeripheralDevice{},
		AudioDevices:    []shared.AudioDevice{},
		Printers:        []shared.Printer{},
		Displays:        []shared.Display{},
		LocalUsers:      []shared.UserWithGroup{},
	})
	for _, k := range inventoryListKeys {
		v, ok := m[k]
		if !ok {
			t.Errorf("key %q left out, want []", k)
			continue
		}
		if string(v) != "[]" {
			t.Errorf("key %q = %s, want []", k, v)
		}
	}
}
