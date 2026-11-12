package yara

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// A v1 bundle without on_write (an older backend) decodes as before, with
// on-write off.
func TestDecode_OnWriteAbsent(t *testing.T) {
	b, err := Decode([]byte(sampleBundle))
	if err != nil {
		t.Fatal(err)
	}
	if b.OnWrite != nil || b.OnWriteEnabled() {
		t.Fatalf("on_write = %+v, want off", b.OnWrite)
	}
}

func TestDecode_OnWrite(t *testing.T) {
	raw := edit(t, func(m map[string]any) {
		m["on_write"] = map[string]any{
			"enabled":     true,
			"paths":       map[string]any{"windows": []any{`%USERPROFILE%\Downloads`}, "darwin": []any{}, "linux": []any{"/srv/drop"}},
			"exclusions":  map[string]any{"linux": []any{"/srv/drop/cache"}},
			"ruleset_ids": []any{rsID},
		}
	})
	b, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := &OnWrite{
		Enabled:    true,
		Paths:      OSPaths{Windows: []string{`%USERPROFILE%\Downloads`}, Darwin: []string{}, Linux: []string{"/srv/drop"}},
		Exclusions: OSPaths{Linux: []string{"/srv/drop/cache"}},
		RulesetIDs: []string{rsID},
	}
	if !reflect.DeepEqual(b.OnWrite, want) || !b.OnWriteEnabled() {
		t.Fatalf("on_write = %+v, want %+v", b.OnWrite, want)
	}
}

// on_write off, or the whole bundle off, leaves nothing to watch.
func TestDecode_OnWriteOff(t *testing.T) {
	for name, fn := range map[string]func(m map[string]any){
		"on_write disabled": func(m map[string]any) {
			m["on_write"] = map[string]any{"enabled": false, "paths": map[string]any{"linux": []any{"/srv"}}}
		},
		"on_write null": func(m map[string]any) { m["on_write"] = nil },
		"bundle disabled": func(m map[string]any) {
			m["enabled"] = false
			m["on_write"] = map[string]any{"enabled": true}
		},
	} {
		b, err := Decode(edit(t, fn))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if b.OnWrite != nil || b.OnWriteEnabled() {
			t.Errorf("%s: on_write = %+v, want nil", name, b.OnWrite)
		}
	}
}

func TestDecode_OnWriteRejects(t *testing.T) {
	many := make([]any, MaxOnWritePaths+1)
	for i := range many {
		many[i] = "/srv"
	}
	for name, ow := range map[string]map[string]any{
		"unknown ruleset":     {"enabled": true, "ruleset_ids": []any{rsID2}},
		"too many paths":      {"enabled": true, "paths": map[string]any{"linux": many}},
		"too many exclusions": {"enabled": true, "exclusions": map[string]any{"darwin": many}},
		"empty path":          {"enabled": true, "paths": map[string]any{"windows": []any{""}}},
		"long path":           {"enabled": true, "paths": map[string]any{"linux": []any{"/" + strings.Repeat("a", MaxPathLen)}}},
		"NUL in path":         {"enabled": true, "exclusions": map[string]any{"linux": []any{"/tmp/\x00x"}}},
	} {
		_, err := Decode(edit(t, func(m map[string]any) { m["on_write"] = ow }))
		if !errors.Is(err, ErrInvalidBundle) {
			t.Errorf("%s: err = %v, want ErrInvalidBundle", name, err)
		}
	}
	// A disabled on_write isn't checked: it is dropped.
	if _, err := Decode(edit(t, func(m map[string]any) {
		m["on_write"] = map[string]any{"enabled": false, "ruleset_ids": []any{rsID2}}
	})); err != nil {
		t.Errorf("disabled on_write with a bad ruleset id: %v", err)
	}
}

func TestOnWriteEnabled_Nil(t *testing.T) {
	var b *Bundle
	if b.OnWriteEnabled() {
		t.Error("nil bundle reports on-write")
	}
}
