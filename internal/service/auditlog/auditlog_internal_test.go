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
