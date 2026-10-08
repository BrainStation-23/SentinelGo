package supabase_test

// Wire contract for every operation: exact method, raw path, query, apikey,
// Authorization and body keys. These are the requests the agent has always
// sent (or, for token refresh, the one it should always have sent); a change
// here changes what the backend sees, so it must be deliberate.

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"sentinelgo/internal/supabase"
	"sentinelgo/internal/supabase/supabasetest"
)

func TestWireContract(t *testing.T) {
	const userJWT = "user-jwt"
	tests := []struct {
		name       string
		route      string // "METHOD /path" scripted on the fake
		respBody   string
		call       func(ctx context.Context, c *supabase.Client) error
		wantMethod string
		wantPath   string
		wantQuery  string
		wantAuth   string // "" means the header must be absent
		wantKeys   []string
	}{
		{
			name:     "rpc",
			route:    "POST /rest/v1/rpc/agent_enqueue_software",
			respBody: `{"success":true}`,
			call: func(ctx context.Context, c *supabase.Client) error {
				return c.RPC(ctx, "agent_enqueue_software", map[string]any{"p_device_id": "d", "p_payload": []int{1}}, nil)
			},
			wantMethod: "POST", wantPath: "/rest/v1/rpc/agent_enqueue_software",
			wantAuth: "Bearer " + userJWT, wantKeys: []string{"p_device_id", "p_payload"},
		},
		{
			name:     "refresh uses anon apikey and no bearer",
			route:    "POST /auth/v1/token",
			respBody: `{"access_token":"a","refresh_token":"r","token_type":"bearer","expires_in":3600}`,
			call: func(ctx context.Context, c *supabase.Client) error {
				_, err := c.RefreshSession(ctx, "rt-1")
				return err
			},
			wantMethod: "POST", wantPath: "/auth/v1/token", wantQuery: "grant_type=refresh_token",
			wantAuth: "", wantKeys: []string{"refresh_token"},
		},
		{
			name:     "agent-login has no bearer",
			route:    "POST /functions/v1/agent-login",
			respBody: `{"access_token":"a","refresh_token":"r","expires_in":3600}`,
			call: func(ctx context.Context, c *supabase.Client) error {
				return c.InvokeFunction(ctx, "agent-login", map[string]string{"agent_id": "a", "agent_secret": "s"}, nil)
			},
			wantMethod: "POST", wantPath: "/functions/v1/agent-login",
			wantAuth: "", wantKeys: []string{"agent_id", "agent_secret"},
		},
		{
			name:     "agent-releases download",
			route:    "GET /storage/v1/object/agent-releases/v2.1.6/sentinelgo-linux-amd64",
			respBody: "binary",
			call: func(ctx context.Context, c *supabase.Client) error {
				_, err := c.Download(ctx, "agent-releases", "v2.1.6/sentinelgo-linux-amd64", false, &bytes.Buffer{}, 0)
				return err
			},
			wantMethod: "GET", wantPath: "/storage/v1/object/agent-releases/v2.1.6/sentinelgo-linux-amd64",
			wantAuth: "Bearer " + userJWT,
		},
		{
			name:     "command-scripts download",
			route:    "GET /storage/v1/object/authenticated/command-scripts/cmd-1/linux.sh",
			respBody: "#!/bin/sh",
			call: func(ctx context.Context, c *supabase.Client) error {
				_, err := c.Download(ctx, "command-scripts", "cmd-1/linux.sh", true, &bytes.Buffer{}, 10<<20)
				return err
			},
			wantMethod: "GET", wantPath: "/storage/v1/object/authenticated/command-scripts/cmd-1/linux.sh",
			wantAuth: "Bearer " + userJWT,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := supabasetest.New(t)
			method, path, _ := strings.Cut(tc.route, " ")
			fake.Handle(method, path, supabasetest.Response{Body: tc.respBody})
			c := fake.Client(func() string { return userJWT })

			if err := tc.call(context.Background(), c); err != nil {
				t.Fatalf("call: %v", err)
			}
			reqs := fake.Requests()
			if len(reqs) != 1 {
				t.Fatalf("got %d requests, want 1", len(reqs))
			}
			r := reqs[0]
			if r.Method != tc.wantMethod || r.Path != tc.wantPath || r.RawQuery != tc.wantQuery {
				t.Errorf("request = %s %s?%s, want %s %s?%s", r.Method, r.Path, r.RawQuery, tc.wantMethod, tc.wantPath, tc.wantQuery)
			}
			if got := r.Header.Get("apikey"); got != supabasetest.AnonKey {
				t.Errorf("apikey = %q, want the anon key", got)
			}
			if got := r.Header.Get("Authorization"); got != tc.wantAuth {
				t.Errorf("Authorization = %q, want %q", got, tc.wantAuth)
			}
			if !strings.HasPrefix(r.Header.Get("X-Client-Info"), "sentinelgo/") {
				t.Errorf("X-Client-Info = %q, want sentinelgo/<version>", r.Header.Get("X-Client-Info"))
			}
			if tc.wantKeys != nil {
				var body map[string]json.RawMessage
				if err := json.Unmarshal(r.Body, &body); err != nil {
					t.Fatalf("body is not a JSON object: %v (%s)", err, r.Body)
				}
				var keys []string
				for k := range body {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				if strings.Join(keys, ",") != strings.Join(tc.wantKeys, ",") {
					t.Errorf("body keys = %v, want %v", keys, tc.wantKeys)
				}
			}
		})
	}
}

// TestStorageURL_ByteIdentical pins the exact Storage URLs: no escaping, no
// slash normalisation. The updater depends on these never changing.
func TestStorageURL_ByteIdentical(t *testing.T) {
	c := supabase.New("https://proj.supabase.co", "anon", nil)
	tests := []struct {
		bucket, path string
		authed       bool
		want         string
	}{
		{"agent-releases", "v2.1.6/sentinelgo-windows-amd64.exe", false,
			"https://proj.supabase.co/storage/v1/object/agent-releases/v2.1.6/sentinelgo-windows-amd64.exe"},
		{"agent-releases", "v2.1.6/sentinelgo-windows-amd64.exe.sig", false,
			"https://proj.supabase.co/storage/v1/object/agent-releases/v2.1.6/sentinelgo-windows-amd64.exe.sig"},
		{"command-scripts", "commands/9668bfbe/darwin.sh", true,
			"https://proj.supabase.co/storage/v1/object/authenticated/command-scripts/commands/9668bfbe/darwin.sh"},
		{"command-scripts", "a b/ü?x=1", true,
			"https://proj.supabase.co/storage/v1/object/authenticated/command-scripts/a b/ü?x=1"},
	}
	for _, tc := range tests {
		if got := c.StorageURL(tc.bucket, tc.path, tc.authed); got != tc.want {
			t.Errorf("StorageURL(%q, %q, %v) = %q, want %q", tc.bucket, tc.path, tc.authed, got, tc.want)
		}
	}
}
