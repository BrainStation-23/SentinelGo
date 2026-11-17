package scan

import (
	"strings"
	"testing"

	"sentinelgo/internal/yara/engine"
)

// The skip cache and checkpoints are keyed by the engine version too: a new
// engine can compile rules the old one skipped (pe in go-yara 0.10), so files
// the old engine found clean must be scanned again.
func TestRulesKeyIncludesEngineVersion(t *testing.T) {
	k := rulesKey(bundle(), nil)
	want := engine.Name + "@" + engine.EngineVersion() + ";"
	if !strings.HasPrefix(k, want) || !strings.Contains(k, "@4") {
		t.Errorf("rulesKey = %q, want prefix %q and the ruleset revision", k, want)
	}
}
