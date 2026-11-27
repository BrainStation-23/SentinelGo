package mdmenroll

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
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

	data, err := ProfileFetcher(client, retry)(context.Background())
	if err != nil || string(data) != "<?xml p" || gotDevice != "" || retried != 1 {
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
	if _, err := ProfileFetcher(client, nil)(context.Background()); err == nil || !strings.Contains(err.Error(), "doesn't offer MDM enrollment") {
		t.Errorf("err = %v", err)
	}
}

func TestWindowsEnrollmentFetcher(t *testing.T) {
	answer := map[string]string{"discovery_url": "https://mdm.example.com/EnrollmentServer/Discovery.svc", "upn": "alice@corp.com", "access_token": "tok"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(answer)
	}))
	defer srv.Close()
	client := func() *supabase.Client { return supabase.New(srv.URL, "anon", func() string { return "t" }) }
	got, err := WindowsEnrollmentFetcher(client, nil)(context.Background())
	if err != nil || got.UPN != "alice@corp.com" || got.AccessToken != "tok" {
		t.Fatalf("got %+v err %v", got, err)
	}
	answer["discovery_url"] = "http://mdm.example.com/x"
	if _, err := WindowsEnrollmentFetcher(client, nil)(context.Background()); err == nil {
		t.Error("an http discovery URL was accepted")
	}
	answer["discovery_url"], answer["access_token"] = "https://mdm.example.com/x", ""
	if _, err := WindowsEnrollmentFetcher(client, nil)(context.Background()); err == nil {
		t.Error("an answer without a token was accepted")
	}
}

// The signed copy (#569): the RPC names the MDM host's URL and a one-time
// token; the agent POSTs the token and prefers the CMS-signed answer.
func TestProfileFetcher_SignedProfile(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	signed := []byte{0x30, 0x82, 0x01, 0x00, 0xAA}
	// the unsigned profile names the MDM host (httptest's TLS server is 127.0.0.1)
	profileOn := func(host string) []byte {
		return []byte(`<?xml version="1.0"?><plist><dict><key>ServerURL</key>
			<string>https://` + host + `/mdm/connect</string></dict></plist>`)
	}
	bigSigned := append([]byte{0x30}, bytes.Repeat([]byte{0}, maxProfileBytes+1)...)

	for name, tc := range map[string]struct {
		status   int
		body     []byte
		httpOnly bool
		mdmHost  string
		wantSig  bool
		hits     int
	}{
		"signed":           {http.StatusOK, signed, false, "127.0.0.1", true, 1},
		"used token (410)": {http.StatusGone, []byte(`{"error":"used"}`), false, "127.0.0.1", false, 1},
		"can't sign (503)": {http.StatusServiceUnavailable, nil, false, "127.0.0.1", false, 1},
		"not signed":       {http.StatusOK, []byte("<html>proxy page</html>"), false, "127.0.0.1", false, 1},
		"too large":        {http.StatusOK, bigSigned, false, "127.0.0.1", false, 1},
		"http, not https":  {http.StatusOK, signed, true, "127.0.0.1", false, 0},
		// the token never leaves for a host the profile doesn't name
		"another host": {http.StatusOK, signed, false, "mdm.example.com", false, 0},
	} {
		t.Run(name, func(t *testing.T) {
			hits := 0
			web := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits++
				var got struct{ Token string }
				if r.Method != http.MethodPost || r.URL.Path != "/mdm/agent-profile" ||
					json.NewDecoder(r.Body).Decode(&got) != nil || got.Token != token {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write(tc.body)
			}))
			defer web.Close()
			profileURL := web.URL + "/mdm/agent-profile"
			if tc.httpOnly {
				profileURL = strings.Replace(profileURL, "https://", "http://", 1)
			}
			unsigned := profileOn(tc.mdmHost)
			want := unsigned
			if tc.wantSig {
				want = signed
			}
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]string{
					"profile_base64": base64.StdEncoding.EncodeToString(unsigned),
					"profile_url":    profileURL,
					"profile_token":  token,
				})
			}))
			defer api.Close()
			var logs bytes.Buffer
			log.SetOutput(&logs)
			defer log.SetOutput(os.Stderr)

			client := func() *supabase.Client { return supabase.New(api.URL, "anon", func() string { return "tok" }) }
			data, err := profileFetcher(client, nil, web.Client())(context.Background())
			if err != nil || !bytes.Equal(data, want) || hits != tc.hits {
				t.Fatalf("data %q err %v hits %d", data[:min(len(data), 16)], err, hits)
			}
			if strings.Contains(logs.String(), token) {
				t.Fatalf("the token was logged: %s", logs.String())
			}
			if !tc.wantSig && !strings.Contains(logs.String(), "using the unsigned enrollment profile") {
				t.Fatalf("the fallback wasn't logged: %q", logs.String())
			}
		})
	}
}

// An older server sends neither field: nothing changes.
func TestProfileFetcher_OlderServer(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"profile_base64": base64.StdEncoding.EncodeToString([]byte("<?xml old"))})
	}))
	defer api.Close()
	web := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("no web request expected")
		return nil, nil
	})}
	client := func() *supabase.Client { return supabase.New(api.URL, "anon", func() string { return "tok" }) }
	data, err := profileFetcher(client, nil, web)(context.Background())
	if err != nil || string(data) != "<?xml old" {
		t.Fatalf("data %q err %v", data, err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
