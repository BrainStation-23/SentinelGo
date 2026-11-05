package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

// The inventory carries the session helpers' readiness when a source is set
// (#323), and leaves sessions out otherwise.
func TestSessionsSource(t *testing.T) {
	t.Cleanup(func() { SetSessionsSource(nil) })
	marshal := func() string {
		p := AgentUpdatePayload{}
		if f := sessionsSource.Load(); f != nil {
			p.Sessions = (*f)()
		}
		b, _ := json.Marshal(p)
		return string(b)
	}
	if strings.Contains(marshal(), `"sessions"`) {
		t.Fatal("sessions sent without a source")
	}
	SetSessionsSource(func() []SessionReport {
		return []SessionReport{{User: "bob", State: "running", SessionID: "2", Capabilities: map[string]string{"notifications": "disabled:app"}}}
	})
	if got := marshal(); !strings.Contains(got, `"sessions":[{"user":"bob","state":"running","session_id":"2","capabilities":{"notifications":"disabled:app"}}]`) {
		t.Fatal(got)
	}
}
