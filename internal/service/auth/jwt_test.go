package auth

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

// makeJWT builds a signature-less-but-well-formed JWT with the given exp claim.
func makeJWT(exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, exp)))
	return header + "." + payload + ".sig"
}

func TestTokenExpiry(t *testing.T) {
	want := time.Now().Add(time.Hour).Unix()
	got, err := TokenExpiry(makeJWT(want))
	if err != nil {
		t.Fatalf("TokenExpiry: %v", err)
	}
	if got.Unix() != want {
		t.Errorf("TokenExpiry = %d, want %d", got.Unix(), want)
	}

	for _, bad := range []string{"", "notajwt", "a.b", "a.b.c.d", "x.@@@.z"} {
		if _, err := TokenExpiry(bad); err == nil {
			t.Errorf("TokenExpiry(%q) = nil error, want error", bad)
		}
	}
}

// TestTokenExpiry_PaddedBase64Fallback covers the tolerate-padded-variants path:
// a payload encoded with standard padded base64url (which base64.RawURLEncoding
// rejects) must still decode via the base64.URLEncoding fallback.
func TestTokenExpiry_PaddedBase64Fallback(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	want := time.Now().Add(time.Hour).Unix()
	payload := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, want))) // padded
	token := header + "." + payload + ".sig"

	got, err := TokenExpiry(token)
	if err != nil {
		t.Fatalf("TokenExpiry with padded payload: %v", err)
	}
	if got.Unix() != want {
		t.Errorf("TokenExpiry = %d, want %d", got.Unix(), want)
	}
}

func TestTokenExpiry_InvalidJSONPayload(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`not json`))
	token := header + "." + payload + ".sig"

	if _, err := TokenExpiry(token); err == nil {
		t.Error("expected an error for a non-JSON payload")
	}
}

func TestTokenExpiry_MissingExpClaim(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user-1"}`))
	token := header + "." + payload + ".sig"

	if _, err := TokenExpiry(token); err == nil {
		t.Error("expected an error when the exp claim is absent")
	}
}

func TestShouldRefresh(t *testing.T) {
	skew := 5 * time.Minute

	// Fresh token (expires in 1h) -> no refresh.
	if ShouldRefresh(makeJWT(time.Now().Add(time.Hour).Unix()), skew) {
		t.Error("fresh token should not need refresh")
	}
	// Within skew of expiry -> refresh.
	if !ShouldRefresh(makeJWT(time.Now().Add(2*time.Minute).Unix()), skew) {
		t.Error("token within skew should need refresh")
	}
	// Already expired -> refresh.
	if !ShouldRefresh(makeJWT(time.Now().Add(-time.Minute).Unix()), skew) {
		t.Error("expired token should need refresh")
	}
	// Empty / unparseable -> refresh.
	if !ShouldRefresh("", skew) {
		t.Error("empty token should need refresh")
	}
	if !ShouldRefresh("garbage", skew) {
		t.Error("unparseable token should need refresh")
	}
}
