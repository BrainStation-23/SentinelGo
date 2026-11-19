//go:build readonly

package native

import (
	"slices"
	"testing"
)

// readOnlySlugs are the native tasks the read-only build may run (#547):
// they report, sync the DLP policy or update the agent, and change nothing
// else on the device. A new handler is left out of the read-only build until
// it is added here, and only once it is gated or proven harmless.
var readOnlySlugs = []string{
	"agent-update",
	"dlp-sync-policy", "dlp_sync_policy",
	"sync-inventory",
	"sync-packages",
	"sync-services",
	"sync-software",
}

func TestReadOnlyRegistry(t *testing.T) {
	var got []string
	for _, h := range Registry() {
		for _, s := range h.Slugs() {
			got = append(got, s)
			if !slices.Contains(readOnlySlugs, s) {
				t.Errorf("the read-only build registers %q (%T); gate it with a buildflavor constant or add it to readOnlySlugs", s, h)
			}
		}
	}
	for _, s := range readOnlySlugs {
		if !slices.Contains(got, s) {
			t.Errorf("%q is allowed but not registered", s)
		}
	}
}
