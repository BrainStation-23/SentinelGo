package auditlog

import "testing"

func TestAuditLogCategoryKey(t *testing.T) {
	tests := []struct {
		category string
		want     string
	}{
		{"SECURITY_LOG", "security"},
		{"USER_LOG", "security"},
		{"NETWORK_LOG", "network"},
		{"POLICY_LOG", "mdm"},
		{"REMOTE_ACTION_LOG", "mdm"},
		{"SYSTEM_LOG", "system"},
		{"AGENT_LOG", "system"},
		{"STORAGE_LOG", "system"},
		{"", "system"},
		{"UNKNOWN_CATEGORY", "system"},
	}

	for _, tc := range tests {
		t.Run(tc.category, func(t *testing.T) {
			got := auditLogCategoryKey(tc.category)
			if got != tc.want {
				t.Errorf("auditLogCategoryKey(%q) = %q, want %q", tc.category, got, tc.want)
			}
		})
	}
}

func TestParseBatchResult(t *testing.T) {
	// A server before Compliance-OS#828 sends neither field.
	if r := parseBatchResult([]byte(`{"success":true,"enqueued":true}`)); r.Duplicate || r.Window != nil {
		t.Errorf("old response = %+v, want zero", r)
	}
	if r := parseBatchResult(nil); r.Duplicate || r.Window != nil {
		t.Errorf("empty response = %+v, want zero", r)
	}
	r := parseBatchResult([]byte(`{"success":true,"queued":false,"duplicate":true,
		"audit_logs":{"retention_days":3,"accept_after":"2026-11-07T10:00:00.123456+00:00",
		"accept_before":"2026-11-11T10:00:00Z","max_event_data_bytes":10000}}`))
	if !r.Duplicate || r.Window == nil {
		t.Fatalf("result = %+v, want duplicate with a window", r)
	}
	w := r.Window
	if w.RetentionDays != 3 || w.MaxEventDataBytes != 10000 ||
		w.AcceptAfter.UTC().Format("2006-01-02T15") != "2026-11-07T10" || w.AcceptBefore.IsZero() {
		t.Errorf("window = %+v", w)
	}
	if r := parseBatchResult([]byte(`{"audit_logs":{"accept_after":"yesterday"}}`)); r.Window == nil || !r.Window.AcceptAfter.IsZero() {
		t.Errorf("unparseable time should be zero; got %+v", r.Window)
	}
}
