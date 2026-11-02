package mdmenroll

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sentinelgo/internal/supabase"
)

func TestDecodeProfile(t *testing.T) {
	signed := []byte{0x30, 0x82, 0x01, 0x00, 0xAA}
	for name, tc := range map[string]struct {
		in   string
		ok   bool
		want string
	}{
		"signed (CMS)":   {base64.StdEncoding.EncodeToString(signed), true, string(signed)},
		"unsigned plist": {base64.StdEncoding.EncodeToString([]byte("  <?xml version=\"1.0\"?><plist/>")), true, "  <?xml version=\"1.0\"?><plist/>"},
		"empty":          {"", false, ""},
		"not base64":     {"%%%", false, ""},
		"not a profile":  {base64.StdEncoding.EncodeToString([]byte("#!/bin/sh\nrm -rf /")), false, ""},
		"too large":      {strings.Repeat("A", maxProfileBytes*2), false, ""},
	} {
		got, err := decodeProfile(tc.in)
		if (err == nil) != tc.ok || (tc.ok && string(got) != tc.want) {
			t.Errorf("%s: got %q, err %v", name, got, err)
		}
	}
}

func TestProfileFetcher(t *testing.T) {
	var gotDevice string
	retried := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotDevice = r.Header.Get("X-Device-ID")
		if !strings.HasSuffix(r.URL.Path, "/rpc/"+rpcEnrollmentProfile) {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": "PGRST202", "message": "Could not find the function"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"profile_base64": base64.StdEncoding.EncodeToString([]byte("<?xml p"))})
	}))
	defer srv.Close()
	client := func() *supabase.Client { return supabase.New(srv.URL, "anon", func() string { return "tok" }) }
	retry := func(ctx context.Context, fn func() error) error { retried++; return fn() }

	data, err := ProfileFetcher(client, "dev-1", retry)(context.Background())
	if err != nil || string(data) != "<?xml p" || gotDevice != "dev-1" || retried != 1 {
		t.Errorf("data %q err %v device %q retried %d", data, err, gotDevice, retried)
	}
}

// A backend without the RPC yet gives a clear error.
func TestProfileFetcher_NotDeployed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "PGRST202", "message": "Could not find the function"})
	}))
	defer srv.Close()
	client := func() *supabase.Client { return supabase.New(srv.URL, "anon", func() string { return "tok" }) }
	if _, err := ProfileFetcher(client, "d", nil)(context.Background()); err == nil || !strings.Contains(err.Error(), "doesn't offer MDM enrollment") {
		t.Errorf("err = %v", err)
	}
}
