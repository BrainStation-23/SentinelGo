package yara

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestDecodeTaskParams(t *testing.T) {
	p, err := DecodeTaskParams([]byte(`{"scan_id":"` + schID + `","preset":"custom","paths":["/srv"],"ruleset_ids":null,"reason":"campaign X"}`))
	if err != nil {
		t.Fatal(err)
	}
	want := TaskParams{ScanID: schID, Preset: PresetCustom, Paths: []string{"/srv"}, Reason: "campaign X"}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("params = %+v, want %+v", p, want)
	}

	// quick and full ignore paths; no scan_id means the agent mints one.
	p, err = DecodeTaskParams([]byte(`{"preset":"quick","paths":["/ignored"],"ruleset_ids":["` + rsID + `"],"reason":"r"}`))
	if err != nil {
		t.Fatal(err)
	}
	if p.Paths != nil || p.ScanID != "" || !reflect.DeepEqual(p.RulesetIDs, []string{rsID}) {
		t.Fatalf("params = %+v", p)
	}
}

func TestDecodeTaskParams_Rejects(t *testing.T) {
	for name, raw := range map[string]string{
		"not json":       `{`,
		"no preset":      `{"reason":"r"}`,
		"bad preset":     `{"preset":"deep"}`,
		"bad scan id":    `{"preset":"quick","scan_id":"x"}`,
		"custom no path": `{"preset":"custom","paths":[]}`,
		"bad ruleset":    `{"preset":"full","ruleset_ids":["x"]}`,
	} {
		if _, err := DecodeTaskParams([]byte(raw)); !errors.Is(err, ErrInvalidTask) {
			t.Errorf("%s: err = %v, want ErrInvalidTask", name, err)
		}
	}
}

func TestTaskResultShape(t *testing.T) {
	data, err := json.Marshal(TaskResult{ScanID: schID, State: TaskStarted})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"scan_id":"`+schID+`","state":"started","files_scanned":0,"matches":0}` {
		t.Fatalf("result = %s", data)
	}
}
