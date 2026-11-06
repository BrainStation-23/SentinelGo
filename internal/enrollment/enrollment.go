// Package enrollment is first-boot enrollment (#351): an agent installed from
// a generic package, with no config.json, registers itself with a single-use
// token and gets its own agent_id and agent_secret.
//
// The token comes from the device's management system: MDM managed
// preferences on macOS, or enrollment.json next to config.json, which an
// installer can write (the Windows MSI does, #358). The backend binds each
// token to one device, so a copied token is useless elsewhere.
package enrollment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"sentinelgo/internal/config"
	"sentinelgo/internal/supabase"
)

// FileName is the token file an installer can drop next to config.json.
const FileName = "enrollment.json"

// enrollFunction exchanges a token for agent credentials (contract v1,
// Compliance-OS#543; Windows MDM identity and mdm_host, Compliance-OS#555).
// It's public: the anon key gates it, the token authenticates the device.
//
// Request:  {token, serial, provisioning_udid, omadm_device_id, smbios_uuid, os, arch}
//
//	Every identity field is always sent, "" when unknown. provisioning_udid
//	is filled on macOS; omadm_device_id and smbios_uuid on Windows (#398),
//	where the backend's Windows MDM record has no serial.
//
// Response: {agent_id, agent_secret, mdm_host?}
//
//	mdm_host is optional: older backends don't send it, and then the
//	config's value is left as it is.
const enrollFunction = "agent-enroll"

// ErrNoToken means no enrollment token is available yet.
var ErrNoToken = errors.New("no enrollment token found")

// Source is where an enrollment token came from and what to do with it.
type Source struct {
	Token     string
	ServerURL string // the API (Supabase) URL
	AnonKey   string
	Origin    string // where it was found, for logs
	// file is the token file to delete once used; "" for managed preferences.
	file string
}

// Identity is what the backend checks the token against.
type Identity struct {
	Serial           string
	ProvisioningUDID string // macOS
	OMADMDeviceID    string // Windows: the OMA-DM DeviceID of the MDM enrollment
	SMBIOSUUID       string // Windows
}

// Credentials is the backend's answer to a token exchange.
type Credentials struct {
	AgentID     string
	AgentSecret string
	// MDMHost is the deployment's MDM hostname; "" when the backend didn't
	// send one (or sent something that isn't a hostname).
	MDMHost string
}

// Needed reports whether the agent has no usable configuration: no API URL
// at all. An install from a per-agent package or zip always has one, so it
// never enrolls.
func Needed(cfg *config.Config) bool {
	return cfg != nil && strings.TrimSpace(cfg.SupabaseURL) == ""
}

// Find returns the first available token: the token file in the config
// directory, then the platform's managed settings.
func Find(cfg *config.Config) (Source, error) {
	if cfg.Path != "" {
		path := filepath.Join(filepath.Dir(cfg.Path), FileName)
		src, err := readFile(path)
		if err == nil {
			return src, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return Source{}, err
		}
	}
	return platformSource()
}

func readFile(path string) (Source, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- fixed file in the root/SYSTEM-only config directory
	if err != nil {
		return Source{}, err
	}
	var f struct {
		Token     string `json:"enrollment_token"`
		ServerURL string `json:"server_url"`
		AnonKey   string `json:"anon_key"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return Source{}, fmt.Errorf("%s: %w", path, err)
	}
	return validate(Source{Token: f.Token, ServerURL: f.ServerURL, AnonKey: f.AnonKey, Origin: path, file: path})
}

// validate checks a token source: all fields set, the API URL https.
func validate(s Source) (Source, error) {
	s.Token, s.ServerURL, s.AnonKey = strings.TrimSpace(s.Token), strings.TrimSpace(s.ServerURL), strings.TrimSpace(s.AnonKey)
	if s.Token == "" || s.ServerURL == "" || s.AnonKey == "" {
		return Source{}, fmt.Errorf("%s: enrollment token, server URL and API key are all required", s.Origin)
	}
	u, err := url.Parse(s.ServerURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return Source{}, fmt.Errorf("%s: server URL must be https", s.Origin)
	}
	s.ServerURL = strings.TrimSuffix(s.ServerURL, "/")
	return s, nil
}

// ErrRejected means the backend refused the token (expired, used, or bound
// to another device). Retrying the same token won't help; a new one will.
var ErrRejected = errors.New("the enrollment token was rejected")

// httpClient is the client for the exchange; nil means the supabase
// package's default. A var for tests.
var httpClient *http.Client

// Exchange trades the token for this device's agent credentials.
func Exchange(ctx context.Context, src Source, id Identity) (Credentials, error) {
	return exchangeWith(ctx, src, id, httpClient)
}

func exchangeWith(ctx context.Context, src Source, id Identity, hc *http.Client) (Credentials, error) {
	body := map[string]string{
		"token":             src.Token,
		"serial":            id.Serial,
		"provisioning_udid": id.ProvisioningUDID,
		"omadm_device_id":   id.OMADMDeviceID,
		"smbios_uuid":       id.SMBIOSUUID,
		"os":                runtime.GOOS,
		"arch":              runtime.GOARCH,
	}
	var resp struct {
		AgentID     string `json:"agent_id"`
		AgentSecret string `json:"agent_secret"`
		MDMHost     string `json:"mdm_host"`
	}
	var opts []supabase.Option
	if hc != nil {
		opts = append(opts, supabase.WithHTTPClient(hc))
	}
	c := supabase.New(src.ServerURL, src.AnonKey, func() string { return "" }, opts...)
	if err := c.InvokeFunction(ctx, enrollFunction, body, &resp); err != nil {
		if supabase.IsUnauthorized(err) || supabase.IsForbidden(err) || supabase.IsNotFound(err) {
			return Credentials{}, fmt.Errorf("%w: %v", ErrRejected, err)
		}
		return Credentials{}, err
	}
	if resp.AgentID == "" || resp.AgentSecret == "" {
		return Credentials{}, errors.New("the server's answer has no agent credentials")
	}
	return Credentials{AgentID: resp.AgentID, AgentSecret: resp.AgentSecret, MDMHost: mdmHost(resp.MDMHost)}, nil
}

// mdmHost returns h when it's a bare hostname (optionally with a port), as
// config's mdm_host expects ("mdm.example.com"), and "" otherwise. A bad
// value is dropped rather than failing the enrollment: the agent works
// without it, and an admin can still set it in config.json.
func mdmHost(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	u, err := url.Parse("https://" + h)
	if err != nil || u.Host != h || u.User != nil || u.Hostname() == "" {
		return ""
	}
	return h
}

// Apply writes the credentials to cfg, saves config.json and deletes the
// used token file. mdm_host is saved only when the backend sent one and the
// config has none: an admin's value wins. The secret is never logged.
func Apply(cfg *config.Config, src Source, creds Credentials) error {
	cfg.SupabaseURL, cfg.SupabaseKey = src.ServerURL, src.AnonKey
	cfg.AgentID, cfg.AgentSecret = creds.AgentID, creds.AgentSecret
	if creds.MDMHost != "" && strings.TrimSpace(cfg.MDMHost) == "" {
		cfg.MDMHost = creds.MDMHost
	}
	if err := cfg.SaveAtomic(); err != nil {
		return fmt.Errorf("saving config.json: %w", err)
	}
	if src.file != "" {
		if err := os.Remove(src.file); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("enrolled, but the used token file wasn't removed: %w", err)
		}
	}
	return nil
}

// Enroll finds a token and, if there is one, exchanges it and saves the
// result. ErrNoToken means there's nothing to do yet.
func Enroll(ctx context.Context, cfg *config.Config, id Identity) error {
	src, err := Find(cfg)
	if err != nil {
		return err
	}
	creds, err := Exchange(ctx, src, id)
	if err != nil {
		return fmt.Errorf("enrolling with the token from %s: %w", src.Origin, err)
	}
	return Apply(cfg, src, creds)
}

// WriteToken saves a token where Find looks for it: enrollment.json in the
// config directory, readable by SYSTEM/root only. Installers call it through
// `sentinelgo enroll` (e.g. the generic MSI's custom action, #358). The file
// is written to a temp name and renamed, so the agent never reads half of it.
func WriteToken(cfg *config.Config, token, serverURL, anonKey string) (string, error) {
	if cfg.Path == "" {
		return "", errors.New("no config path")
	}
	src, err := validate(Source{Token: token, ServerURL: serverURL, AnonKey: anonKey, Origin: "the enrollment token"})
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(map[string]string{"enrollment_token": src.Token, "server_url": src.ServerURL, "anon_key": src.AnonKey})
	if err != nil {
		return "", err
	}
	path := filepath.Join(filepath.Dir(cfg.Path), FileName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return "", err
	}
	if err := config.SecureFile(tmp); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("securing the token file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return path, nil
}
