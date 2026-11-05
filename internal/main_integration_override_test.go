package internal

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"sentinelgo/internal/config"
	"sentinelgo/internal/dlp/filedlp"
	"sentinelgo/internal/dlp/ipc"
	"sentinelgo/internal/dlp/session"
	dlpsvc "sentinelgo/internal/service/dlp"
	"sentinelgo/internal/supabase"
	"sentinelgo/internal/supabase/supabasetest"
)

// askingSessions answers the override dialog and records notifications.
type askingSessions struct {
	fakeSessions
	asked    ipc.AskOverride
	notified ipc.Notify
}

func (a *askingSessions) AskOverride(_ context.Context, _ string, x ipc.AskOverride) (ipc.OverrideAnswer, error) {
	a.asked = x
	return ipc.OverrideAnswer{Choice: "request", Reason: "audit"}, nil
}

func (a *askingSessions) NotifySession(_ context.Context, _ string, n ipc.Notify) error {
	a.notified = n
	return nil
}

func (a *askingSessions) SessionReadiness(string) (string, bool) { return "dnd", true }

// File DLP reaches one session's helper through sessionNotifier (#336).
func TestSessionNotifier(t *testing.T) {
	s := &askingSessions{}
	n := sessionNotifier{s}
	choice, reason, err := n.AskOverride(context.Background(), "1000", "T", "M", true, false)
	if err != nil || choice != "request" || reason != "audit" || s.asked.Title != "T" || !s.asked.CanOverride || s.asked.CanRequest {
		t.Fatalf("%q %q %v %+v", choice, reason, err, s.asked)
	}
	if err := n.NotifySession(context.Background(), "1000", "T", "B"); err != nil || s.notified.Level != ipc.LevelWarning || s.notified.Message != "B" {
		t.Fatalf("%v %+v", err, s.notified)
	}
	if st, ok := n.SessionReadiness("1000"); !ok || st != "dnd" {
		t.Fatal("readiness")
	}
	var plain session.Service = &fakeSessions{}
	if _, _, err := (sessionNotifier{plain}).AskOverride(context.Background(), "1", "", "", true, true); !errors.Is(err, session.ErrNoHelper) {
		t.Fatalf("no helper: %v", err)
	}
}

// An exception request goes to agent_request_dlp_exception with the
// request's fields.
func TestExceptionRequester(t *testing.T) {
	fake := supabasetest.New(t)
	fake.Handle(http.MethodPost, "/rest/v1/rpc/agent_request_dlp_exception", supabasetest.Response{Status: 200, Body: `{}`})
	svc := dlpsvc.New(func() *supabase.Client { return fake.Client(nil) }, "dev-1")
	mi := &MainIntegration{}
	name := "plan.xlsx"
	send := mi.exceptionRequester(&config.Config{}, svc)
	err := send(context.Background(), filedlp.ExceptionRequest{PolicyID: "p1", Channel: "file.removable", EventID: "e1",
		User: "alice", SHA256: strings.Repeat("ab", 32), FileName: &name, Justification: "audit"})
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Req dlpsvc.ExceptionRequest `json:"p_request"`
	}
	if err := json.Unmarshal(fake.Requests()[0].Body, &body); err != nil || body.Req.EventID != "e1" || *body.Req.File.Name != name {
		t.Fatalf("%v %+v", err, body.Req)
	}
}
