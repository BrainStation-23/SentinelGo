package updater

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"sentinelgo/internal/config"
)

// TestDownloadPaths_ByteIdentical pins the exact Storage paths the updater
// requests for a release binary and its signature. A changed URL would leave
// the fleet unable to update, so these must never drift.
func TestDownloadPaths_ByteIdentical(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.EscapedPath())
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	cfg := &config.Config{SupabaseURL: srv.URL, SupabaseKey: "anon", AccessToken: "jwt"}

	_, _, _ = downloadAndVerify(t.Context(), cfg, "v2.1.6/sentinelgo-windows-amd64.exe", "sum", "v2.1.6/sentinelgo-windows-amd64.exe.sig")
	_ = verifySignature(t.Context(), cfg, writeTempBinary(t, []byte("x")), "v2.1.6/sentinelgo-windows-amd64.exe.sig", nil)

	mu.Lock()
	defer mu.Unlock()
	want := []string{
		"/storage/v1/object/agent-releases/v2.1.6/sentinelgo-windows-amd64.exe",
		"/storage/v1/object/agent-releases/v2.1.6/sentinelgo-windows-amd64.exe.sig",
	}
	if len(paths) != 2 || paths[0] != want[0] || paths[1] != want[1] {
		t.Errorf("paths = %q, want %q", paths, want)
	}
}

// An expired JWT during the download (Storage answers 400 InvalidJWT) is now
// recovered through the AuthRetrier instead of failing the update.
func TestDownloadAndVerify_RecoversExpiredToken(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	binary := []byte("new agent binary")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, binary))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fresh-token" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"statusCode":"400","error":"InvalidJWT","message":"jwt expired"}`))
			return
		}
		switch r.URL.Path {
		case "/storage/v1/object/agent-releases/v9/bin":
			_, _ = w.Write(binary)
		case "/storage/v1/object/agent-releases/v9/bin.sig":
			_, _ = w.Write([]byte(sig))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	cfg := &config.Config{SupabaseURL: srv.URL, SupabaseKey: "anon", AccessToken: "expired-token"}
	r := &fakeRetrier{cfg: cfg}
	setRetrier(t, r)

	prev := PublicKey
	PublicKey = pub
	t.Cleanup(func() { PublicKey = prev })

	newPath, sum, err := downloadAndVerify(t.Context(), cfg, "v9/bin", "", "v9/bin.sig")
	if err != nil {
		t.Fatalf("downloadAndVerify: %v", err)
	}
	defer func() { _ = os.Remove(newPath) }()
	if r.recoveries != 1 {
		t.Errorf("recoveries = %d, want 1", r.recoveries)
	}
	got, _ := os.ReadFile(newPath)
	if string(got) != string(binary) || sum == "" {
		t.Errorf("staged binary = %q (sum %q), want the downloaded bytes", got, sum)
	}
}
