package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// These tests cover the credential-at-rest gap recorded as item 5 in
// docs/telemetry/06-existing-code-observations.md.

func credCfg(t *testing.T) *Config {
	t.Helper()
	return &Config{
		Path:         filepath.Join(t.TempDir(), "config.json"),
		SupabaseURL:  "https://example.supabase.co",
		SupabaseKey:  "anon-key",
		DeviceID:     "dev-1",
		AgentID:      "agent-1",
		AccessToken:  "jwt-access-token-value",
		RefreshToken: "jwt-refresh-token-value",
		AgentSecret:  "super-secret-value",
	}
}

// hasProtection reports whether this build can actually protect credentials.
func hasProtection() bool { return newProtector() != nil }

// ── round trip ───────────────────────────────────────────────────────────────

// TestSecretsSurviveSaveAndLoad is the guarantee everything else depends on: a
// protected credential must come back exactly as it went in. Anything less
// silently breaks authentication on every endpoint.
func TestSecretsSurviveSaveAndLoad(t *testing.T) {
	cfg := credCfg(t)
	if err := cfg.SaveAtomic(); err != nil {
		t.Fatalf("SaveAtomic: %v", err)
	}

	loaded, err := Load(cfg.Path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if loaded.AccessToken != "jwt-access-token-value" {
		t.Errorf("access token = %q, want the original value", loaded.AccessToken)
	}
	if loaded.RefreshToken != "jwt-refresh-token-value" {
		t.Errorf("refresh token = %q, want the original value", loaded.RefreshToken)
	}
	if loaded.AgentSecret != "super-secret-value" {
		t.Errorf("agent secret = %q, want the original value", loaded.AgentSecret)
	}
}

// TestSecretsAreNotPlaintextOnDisk is the actual security assertion. It is the
// one test that would have failed before this change.
func TestSecretsAreNotPlaintextOnDisk(t *testing.T) {
	if !hasProtection() {
		t.Skipf("no credential protection on %s; secrets are documented as "+
			"filesystem-permission-protected only", runtime.GOOS)
	}

	cfg := credCfg(t)
	if err := cfg.SaveAtomic(); err != nil {
		t.Fatalf("SaveAtomic: %v", err)
	}

	raw, err := os.ReadFile(cfg.Path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	onDisk := string(raw)

	for _, secret := range []string{
		"jwt-access-token-value",
		"jwt-refresh-token-value",
		"super-secret-value",
	} {
		if strings.Contains(onDisk, secret) {
			t.Errorf("%q appears verbatim in config.json; the credential was not protected", secret)
		}
	}

	// And the stored form must still be valid JSON carrying the marker, so the
	// file shape is unchanged for anything that reads it as configuration.
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		t.Fatalf("config.json is no longer valid JSON: %v", err)
	}
	stored, _ := probe["access_token"].(string)
	if !strings.HasPrefix(stored, protectedPrefix) {
		t.Errorf("stored access_token = %q, want the %q marker", stored, protectedPrefix)
	}
}

// TestNonSecretFieldsStayReadable pins that protection was applied to the three
// credentials and nothing else — an operator must still be able to read and
// edit config.json.
func TestNonSecretFieldsStayReadable(t *testing.T) {
	cfg := credCfg(t)
	if err := cfg.SaveAtomic(); err != nil {
		t.Fatalf("SaveAtomic: %v", err)
	}

	raw, err := os.ReadFile(cfg.Path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	for _, visible := range []string{"https://example.supabase.co", "dev-1", "agent-1"} {
		if !strings.Contains(string(raw), visible) {
			t.Errorf("%q is no longer readable in config.json; only credentials should be protected", visible)
		}
	}
}

// ── migration ────────────────────────────────────────────────────────────────

// TestPlaintextConfigMigratesWithoutReRegistration is the upgrade path. An
// existing endpoint's config.json is plaintext; loading it must work, and the
// next save must protect it — with the same credentials throughout, or the
// device loses its enrolment.
func TestPlaintextConfigMigratesWithoutReRegistration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	legacy := `{
  "supabase_url": "https://example.supabase.co",
  "supabase_key": "anon-key",
  "device_id": "dev-legacy",
  "agent_id": "agent-legacy",
  "access_token": "legacy-access",
  "refresh_token": "legacy-refresh",
  "agent_secret": "legacy-secret"
}`
	if err := os.WriteFile(path, []byte(legacy), 0600); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load of a plaintext config failed: %v", err)
	}
	if loaded.AgentSecret != "legacy-secret" || loaded.AccessToken != "legacy-access" {
		t.Fatalf("plaintext credentials were not read back verbatim: secret=%q access=%q",
			loaded.AgentSecret, loaded.AccessToken)
	}
	if loaded.AgentID != "agent-legacy" {
		t.Errorf("agent_id = %q; a migration must never reset registration", loaded.AgentID)
	}

	if err := loaded.SaveAtomic(); err != nil {
		t.Fatalf("SaveAtomic after migration: %v", err)
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load after migration: %v", err)
	}
	if reloaded.AgentSecret != "legacy-secret" {
		t.Errorf("agent secret = %q after migration, want legacy-secret", reloaded.AgentSecret)
	}
	if reloaded.AgentID != "agent-legacy" {
		t.Errorf("agent_id = %q after migration, want agent-legacy", reloaded.AgentID)
	}
}

// TestDoubleProtectionIsNotPossible pins that saving repeatedly cannot wrap an
// already-wrapped value, which would make it undecodable after two saves.
func TestDoubleProtectionIsNotPossible(t *testing.T) {
	cfg := credCfg(t)

	for i := 0; i < 3; i++ {
		if err := cfg.SaveAtomic(); err != nil {
			t.Fatalf("SaveAtomic %d: %v", i, err)
		}
		loaded, err := Load(cfg.Path)
		if err != nil {
			t.Fatalf("Load %d: %v", i, err)
		}
		if loaded.AgentSecret != "super-secret-value" {
			t.Fatalf("after %d save(s) the secret decoded to %q", i+1, loaded.AgentSecret)
		}
		cfg = loaded
	}
}

// TestSavingDoesNotMutateTheLiveConfig is the bug this design exists to avoid:
// the running agent reads its bearer token out of the same struct that gets
// saved, so protecting in place would send ciphertext as an Authorization
// header on the very next request.
func TestSavingDoesNotMutateTheLiveConfig(t *testing.T) {
	cfg := credCfg(t)
	if err := cfg.SaveAtomic(); err != nil {
		t.Fatalf("SaveAtomic: %v", err)
	}

	if cfg.AccessToken != "jwt-access-token-value" {
		t.Errorf("in-memory access token became %q after saving; the live config "+
			"was mutated and the next request would send ciphertext as a bearer token",
			cfg.AccessToken)
	}
	if cfg.GetAccessToken() != "jwt-access-token-value" {
		t.Errorf("GetAccessToken returned %q after saving", cfg.GetAccessToken())
	}
	if cfg.AgentSecret != "super-secret-value" {
		t.Errorf("in-memory agent secret became %q after saving", cfg.AgentSecret)
	}
}

// ── empty and absent values ──────────────────────────────────────────────────

// TestEmptyCredentialsStayEmpty pins that an unregistered agent's blank fields
// are not turned into opaque blobs that read as real credentials.
func TestEmptyCredentialsStayEmpty(t *testing.T) {
	cfg := &Config{
		Path:        filepath.Join(t.TempDir(), "config.json"),
		SupabaseURL: "https://example.supabase.co",
		SupabaseKey: "anon-key",
		DeviceID:    "dev-1",
		AgentID:     "agent-1",
	}
	if err := cfg.SaveAtomic(); err != nil {
		t.Fatalf("SaveAtomic: %v", err)
	}

	loaded, err := Load(cfg.Path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.AccessToken != "" || loaded.RefreshToken != "" || loaded.AgentSecret != "" {
		t.Errorf("blank credentials came back non-empty: access=%q refresh=%q secret=%q",
			loaded.AccessToken, loaded.RefreshToken, loaded.AgentSecret)
	}
}

// ── opt-out ──────────────────────────────────────────────────────────────────

// TestProtectionCanBeDisabled pins the rollback escape hatch. A binary older
// than this change cannot read a protected value, so a fleet with an open
// rollback window needs a supported way to stay on plaintext.
func TestProtectionCanBeDisabled(t *testing.T) {
	cfg := credCfg(t)
	cfg.CredentialProtection = CredentialProtectionOff

	if err := cfg.SaveAtomic(); err != nil {
		t.Fatalf("SaveAtomic: %v", err)
	}

	raw, err := os.ReadFile(cfg.Path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(raw), "super-secret-value") {
		t.Error("credential_protection=off did not store plaintext, so an older " +
			"binary could not read this config")
	}

	loaded, err := Load(cfg.Path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.AgentSecret != "super-secret-value" {
		t.Errorf("agent secret = %q with protection off", loaded.AgentSecret)
	}
}

func TestCredentialProtectionDefaultsToAuto(t *testing.T) {
	cfg := &Config{}
	if got := cfg.GetCredentialProtection(); got != CredentialProtectionAuto {
		t.Errorf("default credential protection = %q, want %q", got, CredentialProtectionAuto)
	}

	// An unrecognised value must not silently disable protection.
	cfg.CredentialProtection = "nonsense"
	if got := cfg.GetCredentialProtection(); got != CredentialProtectionAuto {
		t.Errorf("unrecognised mode %q resolved to %q, want %q — a typo must not "+
			"turn a security control off", "nonsense", got, CredentialProtectionAuto)
	}
}

// ── failure handling ─────────────────────────────────────────────────────────

// TestUnreadableCredentialDoesNotYieldAnEmptySecretSilently pins that a
// credential which cannot be unprotected — a config copied from another
// machine, which is precisely what machine-bound protection makes useless — is
// reported rather than quietly becoming "".
func TestUnreadableCredentialDoesNotYieldAnEmptySecretSilently(t *testing.T) {
	corrupt := wrap(protectorDPAPI, "bm90LXJlYWxseS1hLWJsb2I=")

	got, err := unprotectValue(corrupt)
	if err == nil {
		t.Fatal("an unreadable protected credential returned no error")
	}
	if got != "" {
		t.Errorf("unprotectValue returned %q alongside its error", got)
	}
	if strings.Contains(err.Error(), "bm90LXJlYWxseS1hLWJsb2I") {
		t.Error("the error message contains the stored credential body")
	}
}

// TestUnknownFormatVersionIsRejected pins forward compatibility: a value written
// by a newer format must be refused, not misread.
func TestUnknownFormatVersionIsRejected(t *testing.T) {
	future := protectedPrefix + protectorDPAPI + ":v99:abcd"
	if _, err := unprotectValue(future); err == nil {
		t.Error("a future format version was accepted")
	}
}

// TestPlaintextPassesThroughUnprotect is the compatibility rule stated as a
// test: anything without the marker is a legacy plaintext value.
func TestPlaintextPassesThroughUnprotect(t *testing.T) {
	for _, v := range []string{"", "plain-token", "eyJhbGciOiJIUzI1NiJ9.abc.def"} {
		got, err := unprotectValue(v)
		if err != nil {
			t.Errorf("unprotectValue(%q) errored: %v", v, err)
		}
		if got != v {
			t.Errorf("unprotectValue(%q) = %q, want it unchanged", v, got)
		}
	}
}

// TestMechanismIsReportedHonestly pins that the agent never claims a protection
// it does not have — the exact failure mode of the EncryptSensitiveData() claim
// this work removed.
func TestMechanismIsReportedHonestly(t *testing.T) {
	cfg := &Config{}
	mech := cfg.CredentialProtectionMechanism()

	if hasProtection() {
		if mech == "" || strings.HasPrefix(mech, "none") {
			t.Errorf("mechanism = %q on a platform that has protection", mech)
		}
	} else if !strings.HasPrefix(mech, "none") {
		t.Errorf("mechanism = %q on %s, which has no protection implemented; it "+
			"must not claim one", mech, runtime.GOOS)
	}

	cfg.CredentialProtection = CredentialProtectionOff
	if got := cfg.CredentialProtectionMechanism(); !strings.HasPrefix(got, "none") {
		t.Errorf("mechanism = %q with protection disabled, want it reported as none", got)
	}
}

// ── protector contract ───────────────────────────────────────────────────────

// TestProtectorRoundTripsAwkwardValues exercises the platform mechanism
// directly with values that have broken naive implementations: non-ASCII,
// embedded NULs, and a long JWT-shaped string.
func TestProtectorRoundTripsAwkwardValues(t *testing.T) {
	p := newProtector()
	if p == nil {
		t.Skipf("no credential protection on %s", runtime.GOOS)
	}

	cases := []string{
		"simple",
		strings.Repeat("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.", 40),
		"ünïcødé-sécret-🔐",
		"with\x00embedded\x00nul",
		strings.Repeat("x", 8192),
	}
	for _, want := range cases {
		body, err := p.Protect(want)
		if err != nil {
			t.Fatalf("Protect(%.20q…): %v", want, err)
		}
		if strings.Contains(body, want) {
			t.Errorf("the protected body contains the plaintext for %.20q…", want)
		}
		got, err := p.Unprotect(body)
		if err != nil {
			t.Fatalf("Unprotect(%.20q…): %v", want, err)
		}
		if got != want {
			t.Errorf("round trip changed the value: got %.40q…, want %.40q…", got, want)
		}
	}
}
