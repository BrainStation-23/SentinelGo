package agent

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sentinelgo/internal/config"
	"sentinelgo/internal/osinfo/shared"
	"sentinelgo/internal/yara"
)

// The inventory carries the threat hunting summary when the service runs
// YARA (#416), and leaves it out otherwise.
func TestUpdateAgentInfo_YARASummary(t *testing.T) {
	t.Cleanup(func() { SetYARASource(nil) })
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()
	cfg := &config.Config{SupabaseURL: server.URL, AccessToken: "t", DeviceID: "d"}
	send := func() {
		t.Helper()
		if err := NewAgentService().UpdateAgentInfo(context.Background(), cfg, &shared.SystemInfo{}); err != nil {
			t.Fatal(err)
		}
	}
	send()
	if strings.Contains(body, `"yara"`) {
		t.Fatalf("yara sent without a source: %s", body)
	}
	SetYARASource(func() *yara.Summary {
		return &yara.Summary{State: yara.StateOK, LocalEnabled: true, Rulesets: 2, CompiledRules: 7, WorkersHealthy: true}
	})
	send()
	if !strings.Contains(body, `"yara":{"state":"ok","local_enabled":true,"rulesets":2,"compiled_rules":7,"skipped_rules":0,"workers_healthy":true,"queued_events":0}`) {
		t.Fatalf("yara summary missing: %s", body)
	}
}
