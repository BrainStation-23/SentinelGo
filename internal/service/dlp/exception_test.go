package dlp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"sentinelgo/internal/supabase/supabasetest"
)

func TestRequestException(t *testing.T) {
	fake := supabasetest.New(t)
	fake.Handle(http.MethodPost, "/rest/v1/rpc/agent_request_dlp_exception", supabasetest.Response{Status: 200, Body: `{"id":"r1"}`})
	name := "plan.xlsx"
	sha := strings.Repeat("ab", 32)
	err := newService(fake).RequestException(context.Background(), ExceptionRequest{
		PolicyID: "p1", Channel: "file.removable", EventID: "e1", User: "alice",
		File: ExceptionFile{SHA256: sha, Name: &name}, Justification: "audit export"})
	if err != nil {
		t.Fatal(err)
	}
	req := fake.Requests()[0]
	if req.Header.Get("X-Device-ID") != "device-1" {
		t.Errorf("headers %v", req.Header)
	}
	var body struct {
		Request ExceptionRequest `json:"p_request"`
	}
	if err := json.Unmarshal(req.Body, &body); err != nil {
		t.Fatal(err)
	}
	if body.Request.PolicyID != "p1" || body.Request.File.SHA256 != sha || *body.Request.File.Name != name || body.Request.Justification != "audit export" {
		t.Fatalf("p_request %+v", body.Request)
	}

	for _, bad := range []ExceptionRequest{
		{PolicyID: "p1", File: ExceptionFile{SHA256: sha}, Justification: ""},
		{PolicyID: "p1", File: ExceptionFile{SHA256: sha}, Justification: strings.Repeat("x", 1001)},
		{PolicyID: "p1", File: ExceptionFile{SHA256: "short"}, Justification: "x"},
	} {
		if err := newService(fake).RequestException(context.Background(), bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
