package directory

import (
	"context"
	"errors"
	"io/fs"
	"os/exec"
	"testing"

	tel "sentinelgo/internal/telemetry"
)

var _ tel.Collector = (*Collector)(nil)

func TestCollectorMetadata(t *testing.T) {
	c := New()
	if c.Name() != tel.SectionDirectory {
		t.Errorf("Name() = %q, want %q", c.Name(), tel.SectionDirectory)
	}
	if c.Section() != tel.SectionDirectory {
		t.Errorf("Section() = %q, want %q", c.Section(), tel.SectionDirectory)
	}
	if c.SchemaVersion() != 1 {
		t.Errorf("SchemaVersion() = %d, want 1", c.SchemaVersion())
	}
}

// TestCapabilityOwnsKeyAndIsValid does not assert a specific state: which
// state is correct is platform- and host-dependent (a Linux host with neither
// realm nor sssd genuinely is CapUnsupported — see platformCapability in each
// _<os>.go file, and TestApplyEntraOutcome / TestCollect_Integration below for
// the behavioural proof on this host).
func TestCapabilityOwnsKeyAndIsValid(t *testing.T) {
	c := New()
	key, state := c.Capability(context.Background(), tel.CollectorConfig{})
	if key != tel.CapKeyDirectoryJoin {
		t.Errorf("Capability() key = %q, want %q", key, tel.CapKeyDirectoryJoin)
	}
	if !state.Valid() {
		t.Errorf("Capability() state = %q is not a valid CapabilityState", state)
	}
}

// TestApplyEntraOutcome is the regression proof for the review finding: a
// failed dsregcmd/realm/sssd/dsconfigad lookup must never silently collapse
// into a confident "false" result, and the reason it failed must classify
// correctly rather than folding every failure into a generic error.
func TestApplyEntraOutcome(t *testing.T) {
	tests := []struct {
		name       string
		adErr      error
		entraErr   error
		wantStatus tel.Status
		// wantUnchanged means applyEntraOutcome must leave Status/Error alone
		// (the caller's done(adErr, ...) result already stands).
		wantUnchanged bool
	}{
		{
			name:          "both probes succeed",
			adErr:         nil,
			entraErr:      nil,
			wantUnchanged: true, // Status stays whatever done(nil, ...) set: Success
		},
		{
			name:          "AD failed: its own classification must not be overwritten",
			adErr:         exec.ErrNotFound,
			entraErr:      nil,
			wantUnchanged: true, // applyEntraOutcome must no-op; done() already handled adErr
		},
		{
			name:          "AD failed AND Entra failed: AD failure still governs",
			adErr:         exec.ErrNotFound,
			entraErr:      errors.New("dsregcmd: access denied"),
			wantUnchanged: true,
		},
		{
			name:       "AD ok, Entra command not found -> Partial, not silently false",
			adErr:      nil,
			entraErr:   exec.ErrNotFound,
			wantStatus: tel.StatusPartial,
		},
		{
			name:       "AD ok, Entra permission denied -> Partial",
			adErr:      nil,
			entraErr:   fs.ErrPermission,
			wantStatus: tel.StatusPartial,
		},
		{
			name:       "AD ok, Entra generic failure -> Partial",
			adErr:      nil,
			entraErr:   errors.New("dsregcmd: unexpected exit"),
			wantStatus: tel.StatusPartial,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := &tel.CollectorResult{Status: tel.StatusSuccess}
			if tc.adErr != nil {
				// Mirror what Collect does: done(adErr, ...) sets Status/Error
				// from SanitizeError(adErr) before applyEntraOutcome runs.
				status, reason := tel.SanitizeError(tc.adErr)
				result.Status = status
				result.Error = reason
			}
			before := *result

			applyEntraOutcome(result, tc.adErr, tc.entraErr)

			if tc.wantUnchanged {
				if result.Status != before.Status || result.Error != before.Error {
					t.Errorf("applyEntraOutcome changed a result it should have left alone: "+
						"got (%q, %q), want (%q, %q)", result.Status, result.Error, before.Status, before.Error)
				}
				return
			}

			if result.Status != tc.wantStatus {
				t.Errorf("Status = %q, want %q", result.Status, tc.wantStatus)
			}
			if result.Status == tel.StatusSuccess {
				t.Error("a failed Entra probe must never leave Status as Success")
			}
		})
	}
}

// TestCollect_Integration exercises the real platform-specific gathering code
// against this host. Most CI and dev hosts are not domain-joined, so this
// only asserts that collection completes cleanly and that a nil DomainJoined
// (undetermined) is never confused with a confirmed false — not any
// particular join state.
func TestCollect_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	c := New()
	_, capState := c.Capability(context.Background(), tel.CollectorConfig{})
	if capState != tel.CapSupported {
		t.Skipf("directory-join detection unsupported on this host: %s", capState)
	}

	payload, res := c.Collect(context.Background(), tel.CollectorConfig{})
	if !res.Status.OK() {
		t.Errorf("Collect() status = %q, error = %q", res.Status, res.Error)
	}

	p, ok := payload.(Payload)
	if !ok {
		t.Fatalf("payload type = %T, want directory.Payload", payload)
	}
	if res.Status == tel.StatusSuccess && p.DomainJoined == nil {
		t.Error("Status is Success but DomainJoined is nil; a successful AD probe must set it")
	}

	domainJoined := "nil"
	if p.DomainJoined != nil {
		domainJoined = boolStr(*p.DomainJoined)
	}
	entraJoined := "nil"
	if p.EntraJoined != nil {
		entraJoined = boolStr(*p.EntraJoined)
	}
	t.Logf("directory: domain_joined=%s domain=%q entra_joined=%s tenant_id=%q device_id=%q source=%q status=%q",
		domainJoined, p.Domain, entraJoined, p.TenantID, p.DeviceID, res.Source, res.Status)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
