package version

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		name         string
		raw          string
		wantKind     Kind
		wantSemver   string
		wantDirty    bool
		wantAhead    int
		wantCommit   string
		wantPreRel   string
		wantCompares bool
	}{
		{
			name:         "clean release tag",
			raw:          "v3.2.8",
			wantKind:     KindRelease,
			wantSemver:   "v3.2.8",
			wantCompares: true,
		},
		{
			name:         "release without leading v",
			raw:          "3.2.8",
			wantKind:     KindRelease,
			wantSemver:   "v3.2.8",
			wantCompares: true,
		},
		{
			name:         "release candidate",
			raw:          "v4.0.0-rc.1",
			wantKind:     KindRelease,
			wantSemver:   "v4.0.0",
			wantPreRel:   "rc.1",
			wantCompares: true,
		},
		{
			// The exact string this endpoint was reporting.
			name:       "git describe with dirty tree",
			raw:        "v3.2.6-4-g40f52e7-dirty",
			wantKind:   KindDevelopment,
			wantSemver: "v3.2.6",
			wantDirty:  true,
			wantAhead:  4,
			wantCommit: "40f52e7",
		},
		{
			name:       "git describe clean tree",
			raw:        "v3.2.6-4-g40f52e7",
			wantKind:   KindDevelopment,
			wantSemver: "v3.2.6",
			wantAhead:  4,
			wantCommit: "40f52e7",
		},
		{
			name:       "tagged commit but dirty tree",
			raw:        "v3.2.8-dirty",
			wantKind:   KindDevelopment,
			wantSemver: "v3.2.8",
			wantDirty:  true,
		},
		{
			name:     "plain go build fallback",
			raw:      DevelopmentFallback,
			wantKind: KindDevelopment,
		},
		{
			name:     "bare commit hash from git describe --always",
			raw:      "40f52e7",
			wantKind: KindDevelopment,
		},
		{
			name:     "empty",
			raw:      "",
			wantKind: KindDevelopment,
		},
		{
			name:     "nonsense",
			raw:      "not-a-version-at-all",
			wantKind: KindDevelopment,
		},
		{
			name:         "whitespace is tolerated",
			raw:          "  v1.2.3  ",
			wantKind:     KindRelease,
			wantSemver:   "v1.2.3",
			wantCompares: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Parse(tc.raw)

			if got.Kind != tc.wantKind {
				t.Errorf("Kind = %q, want %q (reason: %s)", got.Kind, tc.wantKind, got.Reason)
			}
			if got.Semver != tc.wantSemver {
				t.Errorf("Semver = %q, want %q", got.Semver, tc.wantSemver)
			}
			if got.Dirty != tc.wantDirty {
				t.Errorf("Dirty = %v, want %v", got.Dirty, tc.wantDirty)
			}
			if got.CommitsAhead != tc.wantAhead {
				t.Errorf("CommitsAhead = %d, want %d", got.CommitsAhead, tc.wantAhead)
			}
			if got.Commit != tc.wantCommit {
				t.Errorf("Commit = %q, want %q", got.Commit, tc.wantCommit)
			}
			if got.PreRelease != tc.wantPreRel {
				t.Errorf("PreRelease = %q, want %q", got.PreRelease, tc.wantPreRel)
			}

			_, comparable := got.Comparable()
			if comparable != tc.wantCompares {
				t.Errorf("Comparable() ok = %v, want %v", comparable, tc.wantCompares)
			}
		})
	}
}

// TestDevelopmentBuildsNeverCompare is the property that matters most.
//
// The updater used to truncate "v3.2.6-4-g40f52e7-dirty" at the first '-' and
// compare it as 3.2.6 — a version this build was four commits past, and which
// was not even the newest tag in the repository. Every development build shape
// must refuse comparison outright instead.
func TestDevelopmentBuildsNeverCompare(t *testing.T) {
	developmentShapes := []string{
		"v3.2.6-4-g40f52e7-dirty",
		"v3.2.6-4-g40f52e7",
		"v3.2.8-dirty",
		"dev",
		"40f52e7",
		"",
		"garbage",
	}

	for _, raw := range developmentShapes {
		t.Run(raw, func(t *testing.T) {
			info := Parse(raw)
			if info.IsRelease() {
				t.Fatalf("%q classified as a release", raw)
			}
			if _, ok := info.Comparable(); ok {
				t.Fatalf("%q was offered for version comparison", raw)
			}
			if info.Reason == "" {
				t.Errorf("%q gave no reason for being a development build", raw)
			}
		})
	}
}

// TestUnreachableTagCannotBecomeAReportedRelease covers the specific failure
// that made a deployed v3.2.8 endpoint report v3.2.6: git describe walks back to
// the newest tag REACHABLE from HEAD, so a branch missing the newest tags
// produces an older base. That base must never surface as a release version.
func TestUnreachableTagCannotBecomeAReportedRelease(t *testing.T) {
	info := Parse("v3.2.6-4-g40f52e7-dirty")

	if info.IsRelease() {
		t.Fatal("a git-describe base tag was treated as a release version")
	}
	if info.Semver != "v3.2.6" {
		t.Errorf("Semver = %q; the base tag should still be recorded for diagnostics", info.Semver)
	}
	if _, ok := info.Comparable(); ok {
		t.Fatal("the stale base tag was offered for comparison")
	}
}

func TestValidate(t *testing.T) {
	if err := Validate("v3.2.8"); err != nil {
		t.Errorf("Validate(v3.2.8) = %v, want nil", err)
	}
	if err := Validate("v4.0.0-rc.1"); err != nil {
		t.Errorf("Validate(v4.0.0-rc.1) = %v, want nil", err)
	}

	rejected := []string{
		"v3.2.6-4-g40f52e7-dirty",
		"v3.2.8-dirty",
		"dev",
		"",
		"v3.2",
		"v3.2.8.1",
	}
	for _, raw := range rejected {
		if err := Validate(raw); err == nil {
			t.Errorf("Validate(%q) = nil, want an error", raw)
		}
	}
}

// TestValidateRejectsDirtyReleases pins the release-build guarantee: a tagged
// commit built from a modified tree is not that tag, and publishing it as one
// puts an unreproducible artifact into production under a version number that
// claims otherwise.
func TestValidateRejectsDirtyReleases(t *testing.T) {
	err := Validate("v3.2.8-dirty")
	if err == nil {
		t.Fatal("a dirty build passed release validation")
	}
	if got := Parse("v3.2.8-dirty"); !got.Dirty {
		t.Error("Dirty flag was not set")
	}
}

func TestStringMarksDevelopmentBuilds(t *testing.T) {
	if got := Parse("v3.2.8").String(); got != "v3.2.8" {
		t.Errorf("release String() = %q, want %q", got, "v3.2.8")
	}
	if got := Parse("v3.2.6-4-g40f52e7-dirty").String(); got == "v3.2.6-4-g40f52e7-dirty" {
		t.Error("a development build rendered without any marker")
	}
	if got := Parse("").String(); got != "unknown (development build)" {
		t.Errorf("empty String() = %q", got)
	}
}
