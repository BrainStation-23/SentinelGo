package taskstore

import (
	"encoding/json"
	"testing"
)

// command_kind comes from sentinel-ops#403. A null (deleted command) or a
// missing field (older backend) both decode to "", meaning unknown.
func TestTask_DecodeCommandKind(t *testing.T) {
	tests := map[string]string{
		`{"task_id":"t","command_kind":"system"}`: CommandKindSystem,
		`{"task_id":"t","command_kind":"native"}`: CommandKindNative,
		`{"task_id":"t","command_kind":null}`:     "",
		`{"task_id":"t"}`:                         "",
	}
	for in, want := range tests {
		var tk Task
		if err := json.Unmarshal([]byte(in), &tk); err != nil {
			t.Fatalf("Unmarshal(%s): %v", in, err)
		}
		if tk.CommandKind != want {
			t.Errorf("Unmarshal(%s).CommandKind = %q, want %q", in, tk.CommandKind, want)
		}
	}
}
