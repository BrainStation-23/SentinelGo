package mdmenroll

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

const ourEnrollment = "AAAAAAAA-0000-0000-0000-000000000001"

func windowsInfo(enrollments ...shared.MDMEnrollment) *shared.MDMInfo {
	yes := true
	return &shared.MDMInfo{Eligible: &yes, Enrollments: enrollments}
}

func testSyncer(info *shared.MDMInfo) (*Syncer, *[]string, *time.Time) {
	var started []string
	clock := time.Unix(1_800_000_000, 0)
	s := &Syncer{
		OurHost: func() string { return "mdm.example.com" },
		Collect: func(string) *shared.MDMInfo { return info },
		Start:   func(_ context.Context, id string) error { started = append(started, id); return nil },
		Now:     func() time.Time { return clock },
	}
	return s, &started, &clock
}

func TestSync_StartsOurEnrollmentOnlyAndCoalesces(t *testing.T) {
	intune := shared.MDMEnrollment{ID: "BBBBBBBB-0000-0000-0000-000000000002", ServerHost: "enrollment.manage.microsoft.com"}
	ours := shared.MDMEnrollment{ID: ourEnrollment, ServerHost: "mdm.example.com"}
	s, started, clock := testSyncer(windowsInfo(intune, ours))

	out, err := s.Sync(context.Background(), "")
	if err != nil || out.Code != ResultSynced || len(*started) != 1 || (*started)[0] != ourEnrollment {
		t.Fatalf("out %v err %v started %v", out, err, *started)
	}
	*clock = clock.Add(10 * time.Second)
	if out, _ := s.Sync(context.Background(), ""); out.Code != ResultCoalesced || len(*started) != 1 {
		t.Errorf("within the window: %v, started %v", out, *started)
	}
	*clock = clock.Add(syncEvery)
	if out, _ := s.Sync(context.Background(), ""); out.Code != ResultSynced || len(*started) != 2 {
		t.Errorf("after the window: %v, started %v", out, *started)
	}
}

func TestSync_Failures(t *testing.T) {
	// Enrolled only in another MDM: not ours to sync.
	s, started, _ := testSyncer(windowsInfo(shared.MDMEnrollment{ID: "B", ServerHost: "other.example.com"}))
	if _, err := s.Sync(context.Background(), ""); outcomeCode(t, err) != ResultNotEnrolled || len(*started) != 0 {
		t.Errorf("other MDM: %v, started %v", err, *started)
	}

	s, _, _ = testSyncer(windowsInfo())
	s.OurHost = func() string { return "" }
	if _, err := s.Sync(context.Background(), ""); outcomeCode(t, err) != ResultMDMHostUnknown {
		t.Errorf("no host: %v", err)
	}

	s, _, _ = testSyncer(&shared.MDMInfo{}) // a Mac: no Windows eligibility
	if _, err := s.Sync(context.Background(), ""); outcomeCode(t, err) != ResultUnsupportedOS {
		t.Errorf("mac: %v", err)
	}
	s.Start = nil
	if _, err := s.Sync(context.Background(), ""); outcomeCode(t, err) != ResultUnsupportedOS {
		t.Errorf("no starter: %v", err)
	}

	// A failed start doesn't block the next attempt.
	s, _, _ = testSyncer(windowsInfo(shared.MDMEnrollment{ID: ourEnrollment, ServerHost: "mdm.example.com"}))
	calls := 0
	s.Start = func(context.Context, string) error {
		calls++
		if calls == 1 {
			return errors.New("deviceenroller: exit status 1")
		}
		return nil
	}
	if _, err := s.Sync(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "exit status 1") {
		t.Errorf("failed start: %v", err)
	}
	if out, err := s.Sync(context.Background(), ""); err != nil || out.Code != ResultSynced {
		t.Errorf("retry after failure: %v %v", out, err)
	}
}

// The payload's mdm_host overrides the config.
func TestSync_PayloadHost(t *testing.T) {
	s, started, _ := testSyncer(windowsInfo(shared.MDMEnrollment{ID: ourEnrollment, ServerHost: "mdm.override.com"}))
	if out, err := s.Sync(context.Background(), "mdm.override.com"); err != nil || out.Code != ResultSynced || len(*started) != 1 {
		t.Errorf("override: %v %v", out, err)
	}
}

func TestValidEnrollmentID(t *testing.T) {
	for id, want := range map[string]bool{
		ourEnrollment:                            true,
		"{aaaaaaaa-0000-0000-0000-000000000001}": true,
		"aaaaaaaa-0000-0000-0000-00000000000g":   false,
		"x\" & calc & \"":                        false,
		"aaaaaaaa00000000000000000000000000001":  false,
		"":                                       false,
	} {
		if got := validEnrollmentID(id); got != want {
			t.Errorf("validEnrollmentID(%q) = %v, want %v", id, got, want)
		}
	}
}
