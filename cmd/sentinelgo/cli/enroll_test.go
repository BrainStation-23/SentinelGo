package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sentinelgo/internal/config"
	"sentinelgo/internal/enrollment"
)

func enrollConfig(t *testing.T, cfg *config.Config) {
	t.Helper()
	prev := loadDefaultConfig
	loadDefaultConfig = func() (*config.Config, error) { return cfg, nil }
	t.Cleanup(func() { loadDefaultConfig = prev })
}

// The token from stdin lands in enrollment.json, where first-boot
// enrollment finds it (#358).
func TestRunEnroll_WritesTokenFile(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{Path: filepath.Join(dir, "config.json")}
	enrollConfig(t, cfg)

	var out, errOut bytes.Buffer
	code := RunEnroll([]string{"-token", "-", "-server-url", "https://api.example.com/", "-anon-key", "anon"}, strings.NewReader("tok-123\n"), &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	b, err := os.ReadFile(filepath.Join(dir, enrollment.FileName))
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]string
	if err := json.Unmarshal(b, &f); err != nil || f["enrollment_token"] != "tok-123" || f["server_url"] != "https://api.example.com" || f["anon_key"] != "anon" {
		t.Errorf("token file %s (%v)", b, err)
	}
	if strings.Contains(out.String(), "tok-123") {
		t.Error("the token was printed")
	}
	src, err := enrollment.Find(cfg)
	if err != nil || src.Token != "tok-123" {
		t.Errorf("first-boot enrollment doesn't find it: %+v %v", src, err)
	}
	if fi, err := os.Stat(filepath.Join(dir, enrollment.FileName+".tmp")); err == nil {
		t.Errorf("temp file left behind: %v", fi.Name())
	}
}

func TestRunEnroll_Refusals(t *testing.T) {
	dir := t.TempDir()
	enrollConfig(t, &config.Config{Path: filepath.Join(dir, "config.json")})
	var out, errOut bytes.Buffer
	if code := RunEnroll([]string{"-token", "t", "-server-url", "http://api.example.com", "-anon-key", "a"}, nil, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "https") {
		t.Errorf("http URL: exit %d %q", code, errOut.String())
	}
	if code := RunEnroll([]string{"-token", "t"}, nil, &out, &errOut); code != 2 {
		t.Errorf("missing flags: exit %d", code)
	}

	// An agent that's already configured doesn't take a token.
	enrollConfig(t, &config.Config{Path: filepath.Join(dir, "config.json"), SupabaseURL: "https://api.example.com"})
	out.Reset()
	if code := RunEnroll([]string{"-token", "t", "-server-url", "https://api.example.com", "-anon-key", "a"}, nil, &out, &errOut); code != 0 || !strings.Contains(out.String(), "already configured") {
		t.Errorf("configured agent: exit %d %q", code, out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, enrollment.FileName)); err == nil {
		t.Error("a token file was written for a configured agent")
	}
}
