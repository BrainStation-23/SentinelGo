package updater

import (
	"path/filepath"
	"strings"
	"testing"

	"sentinelgo/internal/buildflavor"
	"sentinelgo/internal/config"
)

// otherFlavor is the build this test binary isn't.
func otherFlavor() string {
	if buildflavor.Flavor == buildflavor.FlavorFull {
		return buildflavor.FlavorReadOnly
	}
	return buildflavor.FlavorFull
}

// assetFor is a release asset name of flavor.
func assetFor(flavor string) string {
	if flavor == buildflavor.FlavorReadOnly {
		return "sentinelgo-readonly-linux-amd64"
	}
	return "sentinelgo-linux-amd64"
}

func TestDecideRelease(t *testing.T) {
	own, other := buildflavor.Flavor, otherFlavor()
	cases := []struct {
		name               string
		candidate, current string
		allow              bool
		flavor             string
		want               updateAction
	}{
		{"same version, same build", "v2.1.5", "v2.1.5", false, own, actionNone},
		{"same version, other build", "v2.1.5", "v2.1.5", false, other, actionSwitch},
		{"newer, other build", "v2.1.6", "v2.1.5", false, other, actionUpgrade},
		{"older, other build, no approval", "v2.1.4", "v2.1.5", false, other, actionNone},
		{"older, other build, rollback", "v2.1.4", "v2.1.5", true, other, actionDowngrade},
	}
	for _, tc := range cases {
		got, err := decideRelease(tc.candidate, tc.current, tc.allow, tc.flavor)
		if err != nil || got != tc.want {
			t.Errorf("%s: %v, %v; want %v", tc.name, got, err, tc.want)
		}
	}
	if _, err := decideRelease("v2.1.5", "dev", false, other); err == nil {
		t.Error("a dev build switched builds")
	}
}

func TestReleaseFlavor(t *testing.T) {
	own, other := buildflavor.Flavor, otherFlavor()
	cases := []struct {
		name    string
		r       LatestRelease
		want    string
		wantErr string
	}{
		{"older server: no column", LatestRelease{AssetName: assetFor(own)}, own, ""},
		{"own build", LatestRelease{Flavor: own, AssetName: assetFor(own)}, own, ""},
		{"other build", LatestRelease{Flavor: other, AssetName: assetFor(other)}, other, ""},
		{"name from the path", LatestRelease{Flavor: other, AssetPath: "v1/" + assetFor(other)}, other, ""},
		{"asset of another build", LatestRelease{Flavor: other, AssetName: assetFor(own)}, "", "isn't the " + other + " build"},
		{"no column, other build's asset", LatestRelease{AssetName: assetFor(other)}, "", "isn't the " + own + " build"},
		{"unknown flavor", LatestRelease{Flavor: "Full", AssetName: assetFor(own)}, "", "unknown build flavor"},
	}
	for _, tc := range cases {
		got, err := releaseFlavor(&tc.r)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: %q, %v; want error %q", tc.name, got, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
}

// The server assigns the other build at the running version: it is
// installed and watched like an upgrade, and the marker names the build.
func TestCheckAndApply_SwitchesBuild(t *testing.T) {
	f, cfg := newUpdateFixture(t, "")
	config.Version = f.release.Version
	f.release.Flavor = otherFlavor()
	f.release.AssetName = assetFor(otherFlavor())
	if err := CheckAndApply(t.Context(), cfg); err != nil || len(f.restarted) != 1 {
		t.Fatalf("CheckAndApply() = %v, restarted %v; want the other build installed", err, f.restarted)
	}
	m, err := ReadMarker(filepath.Join(f.cfgDir, markerFileName))
	if err != nil {
		t.Fatalf("no update marker: %v", err)
	}
	if m.ToVersion != f.release.Version || m.ToFlavor != otherFlavor() || len(f.spawned) != 1 {
		t.Errorf("marker %+v, watchdogs %v; want a watched switch to %s", m, f.spawned, otherFlavor())
	}
	// This binary is the old one: the restored agent never confirms the switch.
	if m.installsThis() {
		t.Error("the old build counts as the switch's new binary")
	}
}

// Same version and build, or no flavor column: nothing to do. A row whose
// asset isn't the build it names is refused.
func TestCheckAndApply_NoSwitch(t *testing.T) {
	for name, set := range map[string]func(*LatestRelease){
		"same build": func(r *LatestRelease) { r.Flavor = buildflavor.Flavor },
		"no column":  func(*LatestRelease) {},
	} {
		t.Run(name, func(t *testing.T) {
			f, cfg := newUpdateFixture(t, "")
			config.Version = f.release.Version
			set(&f.release)
			if err := CheckAndApply(t.Context(), cfg); err != nil || len(f.restarted) != 0 {
				t.Fatalf("CheckAndApply() = %v, restarted %v; want nothing", err, f.restarted)
			}
		})
	}
	f, cfg := newUpdateFixture(t, "")
	f.release.Flavor = otherFlavor()
	err := CheckAndApply(t.Context(), cfg)
	if err == nil || !strings.Contains(err.Error(), "isn't the") || len(f.restarted) != 0 {
		t.Fatalf("CheckAndApply() = %v, restarted %v; want a refusal", err, f.restarted)
	}

	// A server without the flavor column offers the other build's asset (a
	// read-only agent offered the full one): refused, not installed.
	f, cfg = newUpdateFixture(t, "")
	f.release.AssetName = assetFor(otherFlavor())
	err = CheckAndApply(t.Context(), cfg)
	if err == nil || !strings.Contains(err.Error(), "isn't the") || len(f.restarted) != 0 {
		t.Fatalf("CheckAndApply() = %v, restarted %v; want a refusal", err, f.restarted)
	}
}

// After a switch the version alone can't tell the binaries apart.
func TestHealth_FlavorTellsBinariesApart(t *testing.T) {
	prev := config.Version
	config.Version = "v3.0.0"
	t.Cleanup(func() { config.Version = prev })
	for _, tc := range []struct {
		m    Marker
		want bool
	}{
		{Marker{ToVersion: "v3.0.0"}, true},
		{Marker{ToVersion: "v3.0.0", ToFlavor: buildflavor.Flavor}, true},
		{Marker{ToVersion: "v3.0.0", ToFlavor: otherFlavor()}, false},
		{Marker{ToVersion: "v3.0.1", ToFlavor: buildflavor.Flavor}, false},
	} {
		if got := tc.m.installsThis(); got != tc.want {
			t.Errorf("%+v: installsThis %v, want %v", tc.m, got, tc.want)
		}
	}

	// The watchdog ignores a health file written by the other build.
	dir := t.TempDir()
	m := &Marker{ToVersion: "v3.0.0", ToFlavor: otherFlavor(), HealthPath: filepath.Join(dir, healthFileName)}
	if err := writeJSONAtomic(m.HealthPath, HealthState{Version: "v3.0.0", Flavor: buildflavor.Flavor, Attempts: 1}); err != nil {
		t.Fatal(err)
	}
	if h := readHealthState(m); h.Attempts != 0 {
		t.Errorf("readHealthState = %+v, want the other build's file ignored", h)
	}
	m.ToFlavor = buildflavor.Flavor
	if h := readHealthState(m); h.Attempts != 1 {
		t.Errorf("readHealthState = %+v, want this build's file", h)
	}
}
