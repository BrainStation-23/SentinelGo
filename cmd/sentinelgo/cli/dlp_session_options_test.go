package cli

import (
	"testing"

	"sentinelgo/internal/buildflavor"
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
	if got := o.OpenProfile != nil; got != buildflavor.MDMEnroll {
		t.Errorf("MDM hooks = %v, want %v", got, buildflavor.MDMEnroll)
	}
	if o := helperOptions(nil); o.SetProxy != nil {
		t.Error("a proxy setter without a desktop proxy")
	}
}
