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
	creds, err := exchangeWith(context.Background(), src, Identity{Serial: "S", ProvisioningUDID: "U"}, srv.Client())
	if err != nil || creds.AgentID != "a-1" || creds.AgentSecret != "s3cret" || creds.MDMHost != "" {
		t.Fatalf("creds %+v err %v", creds, err)
	}
	if body["token"] != "tok" || body["serial"] != "S" || body["provisioning_udid"] != "U" || body["os"] != runtime.GOOS {
		t.Errorf("body = %v", body)
	}
	// Unknown identity fields are sent as "", not left out.
	for _, k := range []string{"omadm_device_id", "smbios_uuid"} {
		if v, ok := body[k]; !ok || v != "" {
			t.Errorf("body[%q] = %q (present %v), want \"\"", k, v, ok)
		}
	}

	rej := enrollServer(t, 401, map[string]string{"message": "token used"}, nil)
	_, err = exchangeWith(context.Background(), Source{Token: "t", ServerURL: rej.URL, AnonKey: "anon"}, Identity{}, rej.Client())
	if !errors.Is(err, ErrRejected) {
		t.Errorf("401: %v, want ErrRejected", err)
	}

	empty := enrollServer(t, 200, map[string]string{}, nil)
	if _, err := exchangeWith(context.Background(), Source{Token: "t", ServerURL: empty.URL, AnonKey: "anon"}, Identity{}, empty.Client()); err == nil {
		t.Error("an answer without credentials was accepted")
	}
}

// Windows sends the OMA-DM DeviceID and SMBIOS UUID next to the serial, since
// the backend's Windows MDM record has no serial (#398).
func TestExchange_WindowsMDMIdentity(t *testing.T) {
	var body map[string]string
	srv := enrollServer(t, 200, map[string]string{"agent_id": "a-1", "agent_secret": "s3cret"}, &body)
	src := Source{Token: "tok", ServerURL: srv.URL, AnonKey: "anon"}
	id := Identity{Serial: "S", OMADMDeviceID: "6F3A1C2B-0D4E-4F5A-9B8C-7D6E5F4A3B2C", SMBIOSUUID: "4c4c4544-0042-3510-8052-b4c04f4e3132"}
	if _, err := exchangeWith(context.Background(), src, id, srv.Client()); err != nil {
		t.Fatal(err)
	}
	if body["omadm_device_id"] != id.OMADMDeviceID || body["smbios_uuid"] != id.SMBIOSUUID || body["serial"] != "S" {
		t.Errorf("body = %v", body)
	}
	if v, ok := body["provisioning_udid"]; !ok || v != "" {
		t.Errorf("provisioning_udid = %q (present %v), want \"\"", v, ok)
	}
}

// mdm_host in the answer is read when it's a hostname and dropped otherwise.
func TestExchange_MDMHost(t *testing.T) {
	for sent, want := range map[string]string{
		"mdm.example.com":         "mdm.example.com",
		" mdm.example.com ":       "mdm.example.com",
		"mdm.example.com:8443":    "mdm.example.com:8443",
		"https://mdm.example.com": "",
		"mdm.example.com/path":    "",
		"user@mdm.example.com":    "",
		"mdm.example.com?x=1":     "",
		"":                        "",
	} {
		srv := enrollServer(t, 200, map[string]string{"agent_id": "a-1", "agent_secret": "s", "mdm_host": sent}, nil)
		creds, err := exchangeWith(context.Background(), Source{Token: "t", ServerURL: srv.URL, AnonKey: "anon"}, Identity{}, srv.Client())
		if err != nil {
			t.Fatalf("%q: %v", sent, err)
		}
		if creds.MDMHost != want {
			t.Errorf("mdm_host %q read as %q, want %q", sent, creds.MDMHost, want)
		}
	}
}

// Apply stores mdm_host from the answer, but never overwrites one already in
// config.json; an answer without it (an older backend) still enrolls.
func TestApply_MDMHost(t *testing.T) {
	src := Source{ServerURL: "https://api.example.com", AnonKey: "anon"}
	for _, tt := range []struct {
		name, existing, sent, want string
	}{
		{"stored when absent", "", "mdm.example.com", "mdm.example.com"},
		{"existing value kept", "mdm.admin.example", "mdm.example.com", "mdm.admin.example"},
		{"older backend", "", "", ""},
		{"older backend keeps existing", "mdm.admin.example", "", "mdm.admin.example"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tempConfig(t)
			cfg.MDMHost = tt.existing
			if err := Apply(cfg, src, Credentials{AgentID: "a-1", AgentSecret: "s3cret", MDMHost: tt.sent}); err != nil {
				t.Fatal(err)
			}
			saved, err := config.Load(cfg.Path)
			if err != nil {
				t.Fatal(err)
			}
			if saved.MDMHost != tt.want || saved.AgentID != "a-1" {
				t.Errorf("saved mdm_host %q agent %q, want %q", saved.MDMHost, saved.AgentID, tt.want)
			}
		})
	}
}

// Enroll saves the credentials to config.json and removes the used token.
func TestEnrollAndApply(t *testing.T) {
	srv := enrollServer(t, 200, map[string]string{"agent_id": "a-1", "agent_secret": "s3cret", "mdm_host": "mdm.example.com"}, nil)
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
	if saved.AgentID != "a-1" || saved.AgentSecret != "s3cret" || saved.SupabaseURL != srv.URL || saved.SupabaseKey != "anon" || saved.DeviceID != cfg.DeviceID || saved.MDMHost != "mdm.example.com" {
		t.Errorf("saved config: id %q url %q key %q device %q mdm_host %q", saved.AgentID, saved.SupabaseURL, saved.SupabaseKey, saved.DeviceID, saved.MDMHost)
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
