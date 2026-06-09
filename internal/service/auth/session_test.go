package auth_test

import (
	"testing"

	"sentinelgo/internal/config"
	serviceauth "sentinelgo/internal/service/auth"
)

func cfgWithToken(token string) *config.Config {
	return &config.Config{
		SupabaseURL:  "https://example.supabase.co",
		SupabaseKey:  "test-key",
		DeviceID:     "test-device",
		AccessToken:  token,
		RefreshToken: "refresh-token",
	}
}

func TestIsAuthenticated_EmptyToken(t *testing.T) {
	sm := serviceauth.NewSessionManager(cfgWithToken(""), nil)
	if sm.IsAuthenticated() {
		t.Error("IsAuthenticated() = true with empty token, want false")
	}
}

func TestIsAuthenticated_WithToken(t *testing.T) {
	sm := serviceauth.NewSessionManager(cfgWithToken("my-valid-token"), nil)
	if !sm.IsAuthenticated() {
		t.Error("IsAuthenticated() = false with non-empty token, want true")
	}
}

func TestIsAuthenticated_NilConfig(t *testing.T) {
	sm := serviceauth.NewSessionManager(nil, nil)
	if sm.IsAuthenticated() {
		t.Error("IsAuthenticated() = true with nil config, want false")
	}
}

func TestGetAccessToken_WithToken(t *testing.T) {
	want := "my-access-token"
	sm := serviceauth.NewSessionManager(cfgWithToken(want), nil)
	got := sm.GetAccessToken()
	if got != want {
		t.Errorf("GetAccessToken() = %q, want %q", got, want)
	}
}

func TestGetAccessToken_EmptyToken(t *testing.T) {
	sm := serviceauth.NewSessionManager(cfgWithToken(""), nil)
	got := sm.GetAccessToken()
	if got != "" {
		t.Errorf("GetAccessToken() = %q, want %q", got, "")
	}
}

func TestGetAccessToken_NilConfig(t *testing.T) {
	sm := serviceauth.NewSessionManager(nil, nil)
	got := sm.GetAccessToken()
	if got != "" {
		t.Errorf("GetAccessToken() with nil config = %q, want %q", got, "")
	}
}
