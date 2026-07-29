package epm_test

import (
	"testing"

	"sentinelgo/internal/config"
	"sentinelgo/internal/epm"
)

// TestTokenTypeMatchesConfigConstants guards the one piece of deliberate
// duplication in this design. internal/config validates epm_windows_token_type
// against its own string constants rather than importing internal/epm, so the
// lowest-level package keeps no dependency on the EPM domain. That is only safe
// while the two sets agree: if they drift, config would accept a value the
// enforcement layer does not recognise (silently defaulting to elevated) or
// reject one it does.
//
// The dependency direction is fine here because this is a test-only import and
// internal/config does not import internal/epm.
func TestTokenTypeMatchesConfigConstants(t *testing.T) {
	for _, tc := range []struct {
		epm    epm.TokenType
		config string
	}{
		{epm.TokenElevated, config.EPMTokenElevated},
		{epm.TokenSystem, config.EPMTokenSystem},
		{epm.TokenFiltered, config.EPMTokenFiltered},
	} {
		if string(tc.epm) != tc.config {
			t.Errorf("epm.TokenType %q != config constant %q", tc.epm, tc.config)
		}
		if !tc.epm.Valid() {
			t.Errorf("epm.TokenType(%q).Valid() = false, want true", tc.epm)
		}
	}
}

// TestConfigDefaultTokenTypeIsValid ensures the value config hands the
// enforcement layer when nothing is configured is one epm actually accepts.
func TestConfigDefaultTokenTypeIsValid(t *testing.T) {
	def := epm.TokenType((&config.Config{}).GetEPMWindowsTokenType())
	if !def.Valid() {
		t.Fatalf("config default token type %q is not a valid epm.TokenType", def)
	}
	if def != epm.TokenElevated {
		t.Errorf("config default = %q, want %q — the default must be the one that "+
			"actually grants privilege", def, epm.TokenElevated)
	}
}
