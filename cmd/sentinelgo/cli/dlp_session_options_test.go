package cli

import (
	"testing"

	"sentinelgo/internal/buildflavor"
	"sentinelgo/internal/mdmenroll"
)

// The helper gets the override prompt, the proxy setter and the MDM hooks
// only in a build that has those features (#547).
func TestHelperOptions(t *testing.T) {
	set := func(string) error { return nil }
	o := helperOptions(set)
	if o.Notify == nil || o.Readiness == nil || len(o.Channels) == 0 {
		t.Fatalf("missing the basics: %+v", o)
	}
	if got := o.AskOverride != nil && o.SetProxy != nil; got != buildflavor.DLPEnforcement {
		t.Errorf("override prompt and proxy = %v, want %v", got, buildflavor.DLPEnforcement)
	}
	// The platform may have no profile hook (Linux); the build decides the rest.
	if want := buildflavor.MDMEnroll && mdmenroll.OpenProfileForUser != nil; (o.OpenProfile != nil) != want {
		t.Errorf("MDM profile hook set = %v, want %v", o.OpenProfile != nil, want)
	}
	if o := helperOptions(nil); o.SetProxy != nil {
		t.Error("a proxy setter without a desktop proxy")
	}
}
