package software

import (
	"slices"
	"testing"
)

// TestSourceContract pins every source value a collector can emit. The server
// (sentinel-ops) rejects items whose source it does not know, so a failure here
// means the server's accepted list must be updated in step (see sentinel-ops#254).
func TestSourceContract(t *testing.T) {
	want := []string{
		"app_store",
		"applications",
		"brave_extensions",
		"chrome_extensions",
		"deb_packages",
		"edge_extensions",
		"firefox_extensions",
		"flatpak_packages",
		"homebrew",
		"homebrew_cask",
		"microsoft_store",
		"programs",
		"rpm_packages",
		"snap_packages",
	}
	got := slices.Clone(allSources)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("source values changed:\n got  %v\n want %v\nupdate the server's accepted sources together with this list", got, want)
	}
}

// assertKnownSource fails unless every item carries a source from allSources.
func assertKnownSource(t *testing.T, items []SoftwareInfo) {
	t.Helper()
	for _, sw := range items {
		if !slices.Contains(allSources, sw.Source) {
			t.Errorf("%q has source %q, which is not in allSources", sw.Name, sw.Source)
		}
	}
}

func TestNormalizeArch(t *testing.T) {
	cases := map[string]string{
		"":             "",
		"(none)":       "",
		"-":            "",
		"arch_other":   "",
		"amd64":        "x64",
		"x86_64":       "x64",
		"X64":          "x64",
		"AMD64":        "x64",
		"arch_i64":     "x64",
		"i386":         "x86",
		"i686":         "x86",
		"X86":          "x86",
		"aarch64":      "arm64",
		"Arm64":        "arm64",
		"arch_arm":     "arm64",
		"arch_ios":     "arm64",
		"armhf":        "arm",
		"Arm":          "arm",
		"arch_arm_i64": "universal",
		"all":          "noarch",
		"noarch":       "noarch",
		"Neutral":      "noarch",
		"ppc64le":      "ppc64le",
		" s390x ":      "s390x",
	}
	for in, want := range cases {
		if got := normalizeArch(in); got != want {
			t.Errorf("normalizeArch(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStripEmail(t *testing.T) {
	cases := map[string]string{
		"Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>": "Ubuntu Developers",
		"Balena Ltd. <hello@balena.io>":                             "Balena Ltd.",
		"Igor Pavlov":                                               "Igor Pavlov",
		"  Spaced  ":                                                "Spaced",
		"<only@address>":                                            "",
		"":                                                          "",
	}
	for in, want := range cases {
		if got := stripEmail(in); got != want {
			t.Errorf("stripEmail(%q) = %q, want %q", in, got, want)
		}
	}
}
