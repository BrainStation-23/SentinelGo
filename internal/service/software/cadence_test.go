package software_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"sentinelgo/internal/config"
	"sentinelgo/internal/models"
	software "sentinelgo/internal/service/software"
)

// These tests cover the two enterprise-scale problems recorded as item 1 in
// docs/telemetry/06-existing-code-observations.md: a full software scan every
// five minutes, and a dedupe fingerprint so unstable that deduplication almost
// never fired.

func installed(name, version, path string) models.SoftwareInfo {
	return models.SoftwareInfo{
		Name:             name,
		DisplayName:      name,
		InstalledVersion: version,
		Source:           "registry",
		Type:             "application",
		FilePath:         path,
	}
}

// ── fingerprint stability ────────────────────────────────────────────────────

// TestOpeningAnApplicationDoesNotChangeTheFingerprint is the headline
// regression test.
//
// LastOpened was hashed as part of SoftwareInfo, so a user launching a single
// application changed the hash of the entire list and forced a full re-upload
// of the whole installed-software inventory. Launching a browser is not a
// change to what is installed.
func TestOpeningAnApplicationDoesNotChangeTheFingerprint(t *testing.T) {
	before := []models.SoftwareInfo{
		installed("Firefox", "128.0", "/usr/bin/firefox"),
		installed("VS Code", "1.90.0", "/usr/bin/code"),
	}

	after := []models.SoftwareInfo{
		installed("Firefox", "128.0", "/usr/bin/firefox"),
		installed("VS Code", "1.90.0", "/usr/bin/code"),
	}
	after[0].LastOpened = time.Now().UTC().Format(time.RFC3339)

	if software.HashSoftwareSnapshot(before, true) != software.HashSoftwareSnapshot(after, true) {
		t.Error("opening an application changed the software fingerprint, so an " +
			"otherwise unchanged inventory would be re-uploaded in full")
	}
}

// TestFirstSeenAtDoesNotChangeTheFingerprint covers the worse of the two
// volatile fields. On macOS FirstSeenAt falls back to time.Now() for any
// application exposing no LastModified date, so those entries differed on every
// single scan and the list could never hash equal.
func TestFirstSeenAtDoesNotChangeTheFingerprint(t *testing.T) {
	scanOne := []models.SoftwareInfo{installed("Safari", "17.5", "/Applications/Safari.app")}
	scanOne[0].FirstSeenAt = "2026-08-21T09:00:00Z"

	scanTwo := []models.SoftwareInfo{installed("Safari", "17.5", "/Applications/Safari.app")}
	scanTwo[0].FirstSeenAt = "2026-08-21T15:30:00Z"

	if software.HashSoftwareSnapshot(scanOne, true) != software.HashSoftwareSnapshot(scanTwo, true) {
		t.Error("a re-derived FirstSeenAt changed the fingerprint, so on macOS the " +
			"inventory could never be recognised as unchanged")
	}
}

// TestFingerprintIsOrderIndependent pins the sort. The list is assembled by
// walking registry hives, package managers and user home directories, none of
// which guarantee a stable enumeration order between runs.
func TestFingerprintIsOrderIndependent(t *testing.T) {
	a := []models.SoftwareInfo{
		installed("Firefox", "128.0", "/usr/bin/firefox"),
		installed("VS Code", "1.90.0", "/usr/bin/code"),
		installed("Git", "2.45.0", "/usr/bin/git"),
	}
	b := []models.SoftwareInfo{a[2], a[0], a[1]}

	if software.HashSoftwareSnapshot(a, true) != software.HashSoftwareSnapshot(b, true) {
		t.Error("the same installed set in a different scan order produced a " +
			"different fingerprint, forcing a spurious re-upload")
	}
}

// TestRealChangesStillChangeTheFingerprint is the other half of the guarantee:
// the fingerprint must not have been stabilised into uselessness.
func TestRealChangesStillChangeTheFingerprint(t *testing.T) {
	base := []models.SoftwareInfo{installed("Firefox", "128.0", "/usr/bin/firefox")}
	baseHash := software.HashSoftwareSnapshot(base, true)

	cases := map[string][]models.SoftwareInfo{
		"an application was upgraded": {installed("Firefox", "129.0", "/usr/bin/firefox")},
		"an application was installed": {
			installed("Firefox", "128.0", "/usr/bin/firefox"),
			installed("VS Code", "1.90.0", "/usr/bin/code"),
		},
		"an application was removed": {},
		"an application moved": {
			installed("Firefox", "128.0", "/opt/firefox/firefox"),
		},
	}

	for name, list := range cases {
		if software.HashSoftwareSnapshot(list, true) == baseHash {
			t.Errorf("%s did not change the fingerprint — the change would never be uploaded", name)
		}
	}
}

// TestCompletenessStillParticipatesInTheFingerprint pins existing behaviour:
// a partial scan becoming a complete scan must upload even when the item list
// is identical.
func TestCompletenessStillParticipatesInTheFingerprint(t *testing.T) {
	list := []models.SoftwareInfo{installed("Firefox", "128.0", "/usr/bin/firefox")}

	if software.HashSoftwareSnapshot(list, false) == software.HashSoftwareSnapshot(list, true) {
		t.Error("a partial scan and a complete scan of the same items hash " +
			"identically, so the transition to a complete inventory would be lost")
	}
}

// ── collection cadence ───────────────────────────────────────────────────────

// TestFirstCollectionIsNeverDelayed pins first-registration behaviour: a
// freshly started agent must scan immediately rather than waiting out an
// interval.
func TestFirstCollectionIsNeverDelayed(t *testing.T) {
	software.ResetSyncState()

	if !software.ShouldCollect(6 * time.Hour) {
		t.Error("the first scan after startup was gated; first registration must " +
			"not be delayed by the collection interval")
	}
}

// TestSubsequentCollectionsAreGated is the cost fix. At the previous cadence
// this was 288 full scans per device per day.
func TestSubsequentCollectionsAreGated(t *testing.T) {
	software.ResetSyncState()

	if !software.ShouldCollect(6 * time.Hour) {
		t.Fatal("first collection should be allowed")
	}

	// Twelve further scheduler ticks, standing in for an hour at the legacy
	// five-minute tick.
	for i := 0; i < 12; i++ {
		if software.ShouldCollect(6 * time.Hour) {
			t.Fatalf("tick %d ran a full scan inside the 6h collection interval", i+1)
		}
	}
}

// TestElapsedIntervalAllowsCollectionAgain pins that the gate opens.
func TestElapsedIntervalAllowsCollectionAgain(t *testing.T) {
	software.ResetSyncState()

	if !software.ShouldCollect(time.Hour) {
		t.Fatal("first collection should be allowed")
	}
	if software.ShouldCollect(time.Hour) {
		t.Fatal("second collection should be gated")
	}

	// Sleep past a short interval rather than passing a nanosecond one: the
	// Windows clock is coarse enough that three consecutive calls can read the
	// same instant, which would make an arbitrarily small interval look
	// un-elapsed and fail this test for a reason that has nothing to do with
	// the gate.
	time.Sleep(20 * time.Millisecond)
	if !software.ShouldCollect(5 * time.Millisecond) {
		t.Error("the gate did not reopen once the interval had elapsed")
	}
}

// TestNonPositiveIntervalDisablesTheGate pins the escape hatch: an operator who
// explicitly wants the old scan-every-tick behaviour can still have it.
func TestNonPositiveIntervalDisablesTheGate(t *testing.T) {
	software.ResetSyncState()

	for i := 0; i < 5; i++ {
		if !software.ShouldCollect(-1) {
			t.Fatalf("call %d was gated despite a negative interval", i)
		}
	}
}

// ── configuration ────────────────────────────────────────────────────────────

func TestSoftwareCadenceDefaults(t *testing.T) {
	cfg := &config.Config{}

	if got := cfg.GetSoftwareCollectInterval(); got != 6*time.Hour {
		t.Errorf("default collect interval = %v, want 6h", got)
	}
	if got := cfg.GetSoftwareResendInterval(); got != 24*time.Hour {
		t.Errorf("default resend interval = %v, want 24h", got)
	}

	// The scheduler tick keeps its legacy default: a tick is cheap now that it
	// no longer implies a scan.
	if got := cfg.GetSoftwareInfoUpdateInterval(); got != 5*time.Minute {
		t.Errorf("default scheduler tick = %v, want 5m", got)
	}
}

// TestSoftwareCadenceIsConfigurable pins that the values are not hardcoded.
func TestSoftwareCadenceIsConfigurable(t *testing.T) {
	cfg := &config.Config{
		SoftwareCollectInterval: config.Duration(90 * time.Minute),
		SoftwareResendInterval:  config.Duration(12 * time.Hour),
	}

	if got := cfg.GetSoftwareCollectInterval(); got != 90*time.Minute {
		t.Errorf("collect interval = %v, want 90m", got)
	}
	if got := cfg.GetSoftwareResendInterval(); got != 12*time.Hour {
		t.Errorf("resend interval = %v, want 12h", got)
	}
}

// TestLegacyConfigStopsScanningEveryFiveMinutes is the upgrade guarantee.
//
// An endpoint upgrading already has "update_interval": "5m0s" written into its
// config file. The fix has to reach that endpoint without anyone editing it,
// which is why the gate is on collection rather than on the scheduler tick.
func TestLegacyConfigStopsScanningEveryFiveMinutes(t *testing.T) {
	legacy := &config.Config{UpdateInterval: config.Duration(5 * time.Minute)}

	if got := legacy.GetSoftwareInfoUpdateInterval(); got != 5*time.Minute {
		t.Errorf("scheduler tick = %v, want the configured 5m to be honoured", got)
	}
	if got := legacy.GetSoftwareCollectInterval(); got != 6*time.Hour {
		t.Errorf("collect interval = %v, want 6h — a legacy update_interval must "+
			"not keep an upgraded agent scanning every five minutes", got)
	}
}

// ── end-to-end: no upload for a usage-only change ────────────────────────────

// TestOpeningAnApplicationDoesNotTriggerAnUpload is the requirement stated at
// the level that matters. The fingerprint tests above prove the hash is stable;
// this proves the consequence — that the agent actually declines to send.
//
// Before the fix, a user launching any single application changed LastOpened,
// which changed the hash of the whole list, which re-uploaded the entire
// installed-software inventory. On a device where someone is working, that
// happened on most 5-minute cycles.
func TestOpeningAnApplicationDoesNotTriggerAnUpload(t *testing.T) {
	var uploads atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		uploads.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"msg_id":1,"queue":"agent_ingest_software"}`))
	}))
	defer server.Close()

	cfg := &config.Config{
		SupabaseURL: server.URL,
		SupabaseKey: "anon-key",
		AccessToken: "jwt",
		DeviceID:    "dev-1",
	}
	svc := software.NewSoftwareService()
	svc.SetSupabaseURL(server.URL)

	software.ResetSyncState()

	list := []models.SoftwareInfo{
		installed("Firefox", "128.0", "/usr/bin/firefox"),
		installed("VS Code", "1.90.0", "/usr/bin/code"),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// First cycle: nothing has been sent yet, so this must upload.
	skipped, err := svc.SendSnapshotByRPCIfChanged(ctx, cfg.DeviceID, list, true, cfg)
	if err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if skipped {
		t.Fatal("the first sync was skipped; a newly registered agent must upload")
	}
	if got := uploads.Load(); got != 1 {
		t.Fatalf("uploads after first sync = %d, want 1", got)
	}

	// The user opens Firefox. Nothing about what is installed has changed.
	opened := []models.SoftwareInfo{
		installed("Firefox", "128.0", "/usr/bin/firefox"),
		installed("VS Code", "1.90.0", "/usr/bin/code"),
	}
	opened[0].LastOpened = time.Now().UTC().Format(time.RFC3339)

	skipped, err = svc.SendSnapshotByRPCIfChanged(ctx, cfg.DeviceID, opened, true, cfg)
	if err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if !skipped {
		t.Error("opening an application forced a re-upload of the entire " +
			"installed-software inventory")
	}
	if got := uploads.Load(); got != 1 {
		t.Errorf("uploads = %d after a usage-only change, want 1", got)
	}

	// A real change must still upload — the dedupe must not have been made
	// permanently sticky.
	installedNew := append(append([]models.SoftwareInfo{}, opened...),
		installed("Slack", "4.38.0", "/usr/bin/slack"))

	skipped, err = svc.SendSnapshotByRPCIfChanged(ctx, cfg.DeviceID, installedNew, true, cfg)
	if err != nil {
		t.Fatalf("third sync: %v", err)
	}
	if skipped {
		t.Error("a newly installed application did not trigger an upload")
	}
	if got := uploads.Load(); got != 2 {
		t.Errorf("uploads = %d after a real install, want 2", got)
	}
}
