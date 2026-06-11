package collector

import (
	"encoding/json"
	"testing"
)

func TestCheckpointInt64(t *testing.T) {
	cases := []struct {
		name    string
		val     interface{}
		want    int64
		wantOK  bool
		present bool
	}{
		{name: "int64 (in-memory)", val: int64(42), want: 42, wantOK: true, present: true},
		{name: "float64 (after JSON)", val: float64(42), want: 42, wantOK: true, present: true},
		{name: "int", val: 42, want: 42, wantOK: true, present: true},
		{name: "json.Number", val: json.Number("42"), want: 42, wantOK: true, present: true},
		{name: "numeric string", val: "42", want: 42, wantOK: true, present: true},
		{name: "non-numeric string", val: "abc", want: 0, wantOK: false, present: true},
		{name: "wrong type", val: []int{1}, want: 0, wantOK: false, present: true},
		{name: "absent", present: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := CheckpointData{}
			if tc.present {
				cp["k"] = tc.val
			}
			got, ok := CheckpointInt64(cp, "k")
			if ok != tc.wantOK || got != tc.want {
				t.Errorf("CheckpointInt64 = (%d, %v), want (%d, %v)", got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestCheckpointFloat64(t *testing.T) {
	cp := CheckpointData{"f": int64(7), "g": float64(7.5), "s": "7.5"}
	if v, ok := CheckpointFloat64(cp, "f"); !ok || v != 7 {
		t.Errorf("int64 -> float64: got (%v, %v)", v, ok)
	}
	if v, ok := CheckpointFloat64(cp, "g"); !ok || v != 7.5 {
		t.Errorf("float64: got (%v, %v)", v, ok)
	}
	if v, ok := CheckpointFloat64(cp, "s"); !ok || v != 7.5 {
		t.Errorf("string -> float64: got (%v, %v)", v, ok)
	}
	if _, ok := CheckpointFloat64(cp, "missing"); ok {
		t.Error("missing key should return ok=false")
	}
}

// TestCheckpointInt64_RoundTrip reproduces the crash scenario: a checkpoint
// value is written as an in-memory int64 on cycle N, then read on cycle N+1.
// The previous bare .(float64) assertion panicked on the in-memory path. This
// asserts both the in-memory and the JSON-persisted paths read back identically.
func TestCheckpointInt64_RoundTrip(t *testing.T) {
	const recordID int64 = 123456

	// In-memory path (map kept between cycles, value stays int64).
	inMem := CheckpointData{"security_record_id": recordID}
	if v, ok := CheckpointInt64(inMem, "security_record_id"); !ok || v != recordID {
		t.Fatalf("in-memory read: got (%d, %v), want (%d, true)", v, ok, recordID)
	}

	// JSON-persisted path (value comes back as float64).
	data, err := json.Marshal(inMem)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var restored CheckpointData
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v, ok := CheckpointInt64(restored, "security_record_id"); !ok || v != recordID {
		t.Fatalf("json-restored read: got (%d, %v), want (%d, true)", v, ok, recordID)
	}
}
