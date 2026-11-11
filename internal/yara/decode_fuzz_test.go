package yara

import (
	"encoding/json"
	"testing"
)

// The bundle, the task params and queued events are untrusted input: none
// may panic, and whatever Decode accepts must stay inside the contract.
func FuzzDecode(f *testing.F) {
	f.Add([]byte(sampleBundle))
	f.Add([]byte(`{"schema_version":1,"version":"v","enabled":false}`))
	f.Add([]byte(`{"schema_version":1,"version":"v","enabled":true,"rulesets":null,"limits":{"max_cpu_percent":-3}}`))
	f.Add([]byte(`{"schema_version":2}`))
	f.Add([]byte(`{"schema_version":1,"version":"v","enabled":true,"on_write":{"enabled":true,"paths":{"linux":["/tmp"]},"ruleset_ids":null}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		b, err := Decode(raw)
		if err != nil {
			return
		}
		if b.Version == "" || len(b.Rulesets) > MaxRulesets {
			t.Fatalf("accepted out-of-contract bundle: %+v", b)
		}
		if !b.Enabled && (b.Rulesets != nil || b.Schedules != nil || b.OnWrite != nil) {
			t.Fatal("disabled bundle kept rules")
		}
		if ow := b.OnWrite; ow != nil {
			if !ow.Enabled || !b.OnWriteEnabled() {
				t.Fatal("kept a disabled on_write")
			}
			for _, l := range []OSPaths{ow.Paths, ow.Exclusions} {
				for _, list := range [][]string{l.Windows, l.Darwin, l.Linux} {
					if len(list) > MaxOnWritePaths {
						t.Fatalf("accepted %d on_write paths", len(list))
					}
				}
			}
			if ow.RulesetIDs != nil && len(b.RulesetsFor(ow.RulesetIDs)) != len(ow.RulesetIDs) {
				t.Fatalf("on_write names rulesets outside the bundle: %v", ow.RulesetIDs)
			}
		}
		var total int64
		for _, r := range b.Rulesets {
			if !validStoragePath(r.StoragePath) || r.Size > MaxRulesetBytes {
				t.Fatalf("accepted ruleset %+v", r)
			}
			total += r.Size
		}
		if total > MaxBundleRuleBytes {
			t.Fatalf("accepted %d bytes of rules", total)
		}
		l := b.Limits
		if l.MaxCPUPercent < 1 || l.MaxCPUPercent > 100 || l.MaxFileBytes <= 0 || l.MaxFilesPerScan <= 0 ||
			l.MaxScanMinutes <= 0 || l.PerFileTimeoutMS <= 0 {
			t.Fatalf("limits out of range: %+v", l)
		}
	})
}

func FuzzDecodeTaskParams(f *testing.F) {
	f.Add([]byte(`{"scan_id":"` + schID + `","preset":"custom","paths":["/srv"],"ruleset_ids":null,"reason":"r"}`))
	f.Add([]byte(`{"preset":"quick"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := DecodeTaskParams(raw)
		if err != nil {
			return
		}
		if !ValidPreset(p.Preset) || (p.Preset == PresetCustom) != (len(p.Paths) > 0) {
			t.Fatalf("accepted %+v", p)
		}
	})
}

func FuzzEventJSON(f *testing.F) {
	m, _ := json.Marshal(Event{EventID: evID, Match: sampleMatch()})
	f.Add(m)
	f.Add([]byte(`{"event_id":"` + evID + `","kind":"scan_summary","scan_id":"` + schID + `","trigger":"scheduled","state":"completed"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var ev Event
		if err := json.Unmarshal(raw, &ev); err != nil {
			return
		}
		if ev.Validate() != nil {
			return
		}
		// A valid event re-encodes and decodes to a valid event.
		data, err := json.Marshal(ev)
		if err != nil {
			t.Fatalf("valid event doesn't encode: %v", err)
		}
		var again Event
		if err := json.Unmarshal(data, &again); err != nil {
			t.Fatalf("re-decode: %v", err)
		}
		if err := again.Validate(); err != nil {
			t.Fatalf("re-decoded event invalid: %v", err)
		}
	})
}
