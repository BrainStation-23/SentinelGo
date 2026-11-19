package buildflavor

import (
	"regexp"
	"testing"
)

func TestFeatures(t *testing.T) {
	got := Features()
	if got == nil {
		t.Fatal("Features() is nil; the payload must always carry the key")
	}
	want := 6
	if ReadOnly {
		want = 0
	}
	if len(got) != want {
		t.Errorf("%s build: Features() = %v, want %d features", Flavor, got, want)
	}
	name := regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	for _, f := range got {
		if !name.MatchString(f) {
			t.Errorf("feature %q doesn't match %s", f, name)
		}
	}
	if Flavor != FlavorFull && Flavor != FlavorReadOnly {
		t.Errorf("Flavor = %q", Flavor)
	}
}
