package dlp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"sentinelgo/internal/dlp"
	"sentinelgo/internal/supabase"
	"sentinelgo/internal/supabase/supabasetest"
)

const rpcPath = "/rest/v1/rpc/agent_get_dlp_policy"

func newService(fake *supabasetest.Server) *Service {
	return New(func() *supabase.Client { return fake.Client(nil) }, "device-1")
}

func TestFetchPolicy_FirstPollSendsNullVersionAndStatus(t *testing.T) {
	fake := supabasetest.New(t)
	fake.Handle(http.MethodPost, rpcPath, supabasetest.Response{Status: 200, Body: `{"schema_version":1,"version":"sha256:v1","enabled":true}`})

	st := &dlp.Status{AppliedVersion: "", AgentVersion: "1.0.0", Capabilities: map[string]string{"clipboard": "supported"}}
	res, err := newService(fake).FetchPolicy(context.Background(), "", st)
	if err != nil {
		t.Fatalf("FetchPolicy: %v", err)
	}
	if res.Unchanged || len(res.Raw) == 0 {
		t.Errorf("result = %+v, want a bundle", res)
	}

	req := fake.Requests()[0]
	if req.Header.Get("X-Device-ID") != "device-1" || req.Header.Get("Authorization") == "" {
		t.Errorf("headers = %v", req.Header)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(req.Body, &body); err != nil {
		t.Fatal(err)
	}
	if string(body["p_known_version"]) != "null" {
		t.Errorf("p_known_version = %s, want null", body["p_known_version"])
	}
	var sent dlp.Status
	if err := json.Unmarshal(body["p_status"], &sent); err != nil || sent.Capabilities["clipboard"] != "supported" {
		t.Errorf("p_status = %s (%v)", body["p_status"], err)
	}
}

func TestFetchPolicy_UnchangedWithoutStatus(t *testing.T) {
	fake := supabasetest.New(t)
	fake.Handle(http.MethodPost, rpcPath, supabasetest.Response{Status: 200, Body: `{"unchanged": true, "version": "sha256:v1"}`})

	res, err := newService(fake).FetchPolicy(context.Background(), "sha256:v1", nil)
	if err != nil || !res.Unchanged {
		t.Fatalf("FetchPolicy = %+v, %v; want unchanged", res, err)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(fake.Requests()[0].Body, &body); err != nil {
		t.Fatal(err)
	}
	if string(body["p_known_version"]) != `"sha256:v1"` {
		t.Errorf("p_known_version = %s", body["p_known_version"])
	}
	if _, sent := body["p_status"]; sent {
		t.Error("p_status sent although nil (it would overwrite the last report)")
	}
}

func TestFetchPolicy_Errors(t *testing.T) {
	tests := []struct {
		name         string
		resp         supabasetest.Response
		status       *dlp.Status
		wantRejected bool
		wantUnauth   bool
	}{
		{"bad status", supabasetest.Response{Status: 400, Body: `{"code":"22023","message":"p_status too large"}`}, &dlp.Status{}, true, false},
		{"22023 without status", supabasetest.Response{Status: 400, Body: `{"code":"22023","message":"x"}`}, nil, false, false},
		{"revoked", supabasetest.Response{Status: 401, Body: `{"code":"42501","message":"not signed in"}`}, nil, false, true},
		{"server error", supabasetest.Response{Status: 503, Body: `{}`}, nil, false, false},
		{"garbage body", supabasetest.Response{Status: 200, Body: `<html>`}, nil, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := supabasetest.New(t)
			fake.Handle(http.MethodPost, rpcPath, tt.resp)
			_, err := newService(fake).FetchPolicy(context.Background(), "v", tt.status)
			if err == nil {
				t.Fatal("FetchPolicy succeeded")
			}
			if got := errors.Is(err, dlp.ErrStatusRejected); got != tt.wantRejected {
				t.Errorf("ErrStatusRejected = %v, want %v (%v)", got, tt.wantRejected, err)
			}
			if got := supabase.IsUnauthorized(err); got != tt.wantUnauth {
				t.Errorf("IsUnauthorized = %v, want %v (%v)", got, tt.wantUnauth, err)
			}
		})
	}
}

// An expired JWT surfaces as unauthorized, so DoWithAuthRetry can recover.
func TestFetchPolicy_ExpiredJWT(t *testing.T) {
	fake := supabasetest.New(t)
	fake.Handle(http.MethodPost, rpcPath, supabasetest.Response{Status: 200, Body: `{"unchanged":true}`})
	fake.ExpireJWT()
	_, err := newService(fake).FetchPolicy(context.Background(), "v", nil)
	if !supabase.IsUnauthorized(err) {
		t.Errorf("err = %v, want unauthorized", err)
	}
}
