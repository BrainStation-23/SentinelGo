package telemetry

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"strings"
	"testing"
)

// TestSanitizeErrorNeverLeaksErrorText is the core privacy guarantee: whatever
// an error's text contains, only a fixed reason code reaches the wire.
//
// This matters because os/exec errors can carry stderr verbatim, and command
// output routinely contains hostnames, usernames, absolute paths, connection
// strings and occasionally credentials.
func TestSanitizeErrorNeverLeaksErrorText(t *testing.T) {
	secret := "hunter2-SUPERSECRET"
	host := "prod-db-07.corp.internal"
	home := `C:\Users\tanjil\AppData\Roaming\creds.json`

	nasty := fmt.Errorf("smartctl failed: password=%s host=%s file=%s", secret, host, home)

	_, reason := SanitizeError(nasty)

	for _, leak := range []string{secret, host, home, "password", "smartctl"} {
		if strings.Contains(reason, leak) {
			t.Fatalf("sanitized reason leaked %q: %s", leak, reason)
		}
	}
	if reason != ReasonUnexpected {
		t.Fatalf("expected %q for an unclassified error, got %q", ReasonUnexpected, reason)
	}
}

// TestSanitizeErrorClassification checks each error shape maps to the intended
// status, so the backend can act on the difference.
func TestSanitizeErrorClassification(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus Status
		wantReason string
	}{
		{"nil", nil, StatusSuccess, ""},
		{"deadline", context.DeadlineExceeded, StatusTimeout, ReasonTimeout},
		{"canceled", context.Canceled, StatusError, ReasonCanceled},
		{"wrapped deadline", fmt.Errorf("collect: %w", context.DeadlineExceeded), StatusTimeout, ReasonTimeout},
		{"not supported", fmt.Errorf("tpm: %w", ErrNotSupported), StatusUnsupported, ReasonNotSupported},
		{"parse failed", fmt.Errorf("smart: %w", ErrParseFailed), StatusError, ReasonParseFailed},
		{"empty output", fmt.Errorf("battery: %w", ErrEmptyOutput), StatusPartial, ReasonEmptyOutput},
		{"wmi", fmt.Errorf("q: %w", ErrWMIQuery), StatusError, ReasonWMIQueryFailed},
		{"command missing", fmt.Errorf("run: %w", exec.ErrNotFound), StatusUnsupported, ReasonCommandNotFound},
		{"permission", fmt.Errorf("open: %w", fs.ErrPermission), StatusPermissionDenied, ReasonPermissionDenied},
		{"not exist", fmt.Errorf("open: %w", fs.ErrNotExist), StatusUnsupported, ReasonNotFound},
		{"unknown", errors.New("something odd"), StatusError, ReasonUnexpected},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, reason := SanitizeError(tc.err)
			if status != tc.wantStatus {
				t.Errorf("status = %q, want %q", status, tc.wantStatus)
			}
			if reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", reason, tc.wantReason)
			}
		})
	}
}

// TestSanitizeErrorMissingToolIsNotAFailure documents an important distinction:
// a tool that is not installed means the data is unobtainable here, not that
// the agent is broken. Reporting it as a failure would make every endpoint
// without smartctl look permanently unhealthy.
func TestSanitizeErrorMissingToolIsNotAFailure(t *testing.T) {
	status, _ := SanitizeError(fmt.Errorf("smartctl: %w", exec.ErrNotFound))
	if status.Failed() {
		t.Fatalf("a missing optional tool must not count as a collector failure, got %q", status)
	}
	if status != StatusUnsupported {
		t.Fatalf("status = %q, want %q", status, StatusUnsupported)
	}
}

// TestSanitizeMessageRedactsSensitiveContent covers the warning path, where
// agent-authored text may still interpolate system values.
func TestSanitizeMessageRedactsSensitiveContent(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		mustNotHave []string
		mustHave    []string
	}{
		{
			name:        "password kv",
			in:          "connect failed password=hunter2 retrying",
			mustNotHave: []string{"hunter2"},
			mustHave:    []string{"<redacted>"},
		},
		{
			name:        "api key kv",
			in:          "api_key: abc123def456 rejected",
			mustNotHave: []string{"abc123def456"},
			mustHave:    []string{"<redacted>"},
		},
		{
			name:        "windows home",
			in:          `could not read C:\Users\tanjil\AppData\config.json`,
			mustNotHave: []string{"tanjil"},
			mustHave:    []string{"<userprofile>"},
		},
		{
			name:        "unix home",
			in:          "could not read /home/tanjil/.ssh/config",
			mustNotHave: []string{"tanjil"},
			mustHave:    []string{"<home>"},
		},
		{
			name:        "macos home",
			in:          "could not read /Users/tanjil/Library/Preferences",
			mustNotHave: []string{"tanjil"},
			mustHave:    []string{"<home>"},
		},
		{
			name:        "long token",
			in:          "unexpected value eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdefgh in output",
			mustNotHave: []string{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcdefgh"},
			mustHave:    []string{"<redacted>"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := SanitizeMessage(tc.in)
			for _, bad := range tc.mustNotHave {
				if strings.Contains(got, bad) {
					t.Errorf("output leaked %q: %s", bad, got)
				}
			}
			for _, want := range tc.mustHave {
				if !strings.Contains(got, want) {
					t.Errorf("output missing %q: %s", want, got)
				}
			}
		})
	}
}

// TestSanitizeMessageBounded verifies the length cap and that truncation does
// not split a multi-byte rune.
func TestSanitizeMessageBounded(t *testing.T) {
	long := strings.Repeat("a b ", 500)
	got := SanitizeMessage(long)
	if len(got) > MaxErrorLen {
		t.Fatalf("length %d exceeds cap %d", len(got), MaxErrorLen)
	}

	multibyte := strings.Repeat("日本語テキスト ", 200)
	got = SanitizeMessage(multibyte)
	if len(got) > MaxErrorLen {
		t.Fatalf("length %d exceeds cap %d", len(got), MaxErrorLen)
	}
	if !strings_ValidUTF8(got) {
		t.Fatalf("truncation split a rune: %q", got)
	}
}

// TestSanitizeMessageStripsControlChars ensures a warning cannot forge log
// lines or carry NUL bytes that Postgres rejects.
func TestSanitizeMessageStripsControlChars(t *testing.T) {
	got := SanitizeMessage("line one\nFAKE LOG ENTRY\r\nmore\x00text")
	for _, bad := range []string{"\n", "\r", "\x00"} {
		if strings.Contains(got, bad) {
			t.Fatalf("control character %q survived: %q", bad, got)
		}
	}
}

// TestSanitizeWarningsCap verifies the MaxWarnings cap and the dropped count,
// so warning loss is reported rather than silent.
func TestSanitizeWarningsCap(t *testing.T) {
	in := make([]string, 0, MaxWarnings+5)
	for i := 0; i < MaxWarnings+5; i++ {
		in = append(in, fmt.Sprintf("warning number %d", i))
	}

	kept, dropped := SanitizeWarnings(in)
	if len(kept) != MaxWarnings {
		t.Fatalf("kept %d warnings, want %d", len(kept), MaxWarnings)
	}
	if dropped != 5 {
		t.Fatalf("dropped = %d, want 5", dropped)
	}
}

// TestCollectorResultSanitize checks the whole-result path used before upload.
func TestCollectorResultSanitize(t *testing.T) {
	res := &CollectorResult{
		Collector: "battery",
		Section:   SectionHealth,
		Status:    StatusError,
		Error:     `failed reading C:\Users\tanjil\battery.log token=abcdef0123456789abcdef0123456789`,
		Warnings:  []string{"password=hunter2", "/home/tanjil/x"},
	}
	res.Sanitize()

	for _, bad := range []string{"tanjil", "hunter2", "abcdef0123456789abcdef0123456789"} {
		if strings.Contains(res.Error, bad) {
			t.Errorf("Error leaked %q: %s", bad, res.Error)
		}
		for _, w := range res.Warnings {
			if strings.Contains(w, bad) {
				t.Errorf("warning leaked %q: %s", bad, w)
			}
		}
	}
}

// TestNewResultRecordsDurationAndSanitizes checks the helper path collectors use.
func TestNewResultRecordsDurationAndSanitizes(t *testing.T) {
	_, done := NewResult("smart", SectionPhysicalDisks)
	res := done(fmt.Errorf("boom: %w", fs.ErrPermission), "exec:smartctl", 3)

	if res.Status != StatusPermissionDenied {
		t.Errorf("status = %q, want %q", res.Status, StatusPermissionDenied)
	}
	if res.Error != ReasonPermissionDenied {
		t.Errorf("error = %q, want %q", res.Error, ReasonPermissionDenied)
	}
	if res.Source != "exec:smartctl" {
		t.Errorf("source = %q", res.Source)
	}
	if res.ItemCount != 3 {
		t.Errorf("itemCount = %d, want 3", res.ItemCount)
	}
	if res.DurationMS < 0 {
		t.Errorf("duration must be non-negative, got %d", res.DurationMS)
	}
}

// strings_ValidUTF8 is a tiny local helper to keep the import list minimal.
func strings_ValidUTF8(s string) bool { return strings.ToValidUTF8(s, "\uFFFD") == s }
