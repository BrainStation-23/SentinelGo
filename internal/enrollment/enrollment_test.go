package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"sentinelgo/internal/config"
)

// tempConfig is a config with defaults and no config.json yet, as on a
// device installed from a generic package.
func tempConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func writeToken(t *testing.T, cfg *config.Config, v map[string]string) string {
	t.Helper()
	path := filepath.Join(filepath.Dir(cfg.Path), FileName)
	b, _ := json.Marshal(v)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestNeeded(t *testing.T) {
	if !Needed(&config.Config{}) {
		t.Error("a config without supabase_url doesn't need enrollment")
	}
	if Needed(&config.Config{SupabaseURL: "https://api.example.com"}) {
		t.Error("an existing install would enroll again")
	}
	if Needed(nil) {
		t.Error("nil config")
	}
}

func TestFind(t *testing.T) {
	cfg := tempConfig(t)
	if _, err := Find(cfg); !errors.Is(err, ErrNoToken) {
		t.Errorf("no token: %v", err)
	}
	writeToken(t, cfg, map[string]string{"enrollment_token": "tok", "server_url": "https://api.example.com/", "anon_key": "anon"})
	src, err := Find(cfg)
	if err != nil || src.Token != "tok" || src.ServerURL != "https://api.example.com" || src.AnonKey != "anon" {
		t.Errorf("src %+v err %v", src, err)
	}
	for name, v := range map[string]map[string]string{
		"http":          {"enrollment_token": "t", "server_url": "http://api.example.com", "anon_key": "a"},
		"missing token": {"server_url": "https://api.example.com", "anon_key": "a"},
		"missing key":   {"enrollment_token": "t", "server_url": "https://api.example.com"},
	} {
		writeToken(t, cfg, v)
		if _, err := Find(cfg); err == nil || errors.Is(err, ErrNoToken) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(cfg.Path), FileName), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Find(cfg); err == nil {
		t.Error("malformed token file accepted")
	}
}

func enrollServer(t *testing.T, status int, resp map[string]string, got *map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/functions/v1/"+enrollFunction || r.Header.Get("apikey") != "anon" {
			t.Errorf("request %s apikey %q", r.URL.Path, r.Header.Get("apikey"))
		}
		if got != nil {
			_ = json.NewDecoder(r.Body).Decode(got)
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestExchange(t *testing.T) {
	var body map[string]string
	srv := enrollServer(t, 200, map[string]string{"agent_id": "a-1", "agent_secret": "s3cret"}, &body)
	src := Source{Token: "tok", ServerURL: srv.URL, AnonKey: "anon", Origin: "test"}
	id, secret, err := exchangeWith(context.Background(), src, Identity{Serial: "S", ProvisioningUDID: "U"}, srv.Client())
	if err != nil || id != "a-1" || secret != "s3cret" {
		t.Fatalf("id %q secret %q err %v", id, secret, err)
	}
	if body["token"] != "tok" || body["serial"] != "S" || body["provisioning_udid"] != "U" || body["os"] != runtime.GOOS {
		t.Errorf("body = %v", body)
	}

	rej := enrollServer(t, 401, map[string]string{"message": "token used"}, nil)
	_, _, err = exchangeWith(context.Background(), Source{Token: "t", ServerURL: rej.URL, AnonKey: "anon"}, Identity{}, rej.Client())
	if !errors.Is(err, ErrRejected) {
		t.Errorf("401: %v, want ErrRejected", err)
	}

	empty := enrollServer(t, 200, map[string]string{}, nil)
	if _, _, err := exchangeWith(context.Background(), Source{Token: "t", ServerURL: empty.URL, AnonKey: "anon"}, Identity{}, empty.Client()); err == nil {
		t.Error("an answer without credentials was accepted")
	}
}

// Enroll saves the credentials to config.json and removes the used token.
func TestEnrollAndApply(t *testing.T) {
	srv := enrollServer(t, 200, map[string]string{"agent_id": "a-1", "agent_secret": "s3cret"}, nil)
	prev := httpClient
	httpClient = srv.Client()
	t.Cleanup(func() { httpClient = prev })

	cfg := tempConfig(t)
	tokenFile := writeToken(t, cfg, map[string]string{"enrollment_token": "tok", "server_url": srv.URL, "anon_key": "anon"})
	if err := Enroll(context.Background(), cfg, Identity{Serial: "S"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(tokenFile); !errors.Is(err, os.ErrNotExist) {
		t.Error("the used token file is still there")
	}
	saved, err := config.Load(cfg.Path)
	if err != nil {
		t.Fatal(err)
	}
	if saved.AgentID != "a-1" || saved.AgentSecret != "s3cret" || saved.SupabaseURL != srv.URL || saved.SupabaseKey != "anon" || saved.DeviceID != cfg.DeviceID {
		t.Errorf("saved config: id %q url %q key %q device %q", saved.AgentID, saved.SupabaseURL, saved.SupabaseKey, saved.DeviceID)
	}
	if Needed(saved) {
		t.Error("still needs enrollment after enrolling")
	}

	// No token: nothing happens.
	cfg2 := tempConfig(t)
	if err := Enroll(context.Background(), cfg2, Identity{}); !errors.Is(err, ErrNoToken) {
		t.Errorf("no token: %v", err)
	}
	if err := Enroll(context.Background(), cfg2, Identity{}); err != nil && strings.Contains(err.Error(), "s3cret") {
		t.Error("an error carries the secret")
	}
}
