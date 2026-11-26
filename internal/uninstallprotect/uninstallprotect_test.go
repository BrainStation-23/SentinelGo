package uninstallprotect

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/supabase"
)

// A test token in the contract's shape (30 Crockford base32 characters in
// six groups of five) and a 16-byte salt. Deliberately repetitive, so secret
// scanners don't take them for real credentials.
var (
	exampleCanonical = strings.Repeat("K1M0P", 6)
	exampleToken     = strings.TrimSuffix(strings.Repeat("K1M0P-", 6), "-")
	exampleSalt      = strings.Repeat("a5", 16)
)

// hashOf is the contract's token_hash: hex(sha256(salt_bytes || canonical)).
func hashOf(t *testing.T, saltHex, canonical string) string {
	t.Helper()
	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(append(salt, canonical...))
	return hex.EncodeToString(sum[:])
}

func enabledState(t *testing.T) *State {
	return &State{Enabled: true, Version: 3, Salt: exampleSalt,
		TokenHash: hashOf(t, exampleSalt, exampleCanonical)}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		exampleToken:                        exampleCanonical,
		strings.Repeat("kim op ", 6) + "\n": exampleCanonical,
		"oOiIlL-01":                         "001111" + "01",
		"":                                  "",
	}
	for in, want := range cases {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheck(t *testing.T) {
	on := enabledState(t)
	cases := []struct {
		name  string
		state *State
		token string
		want  Decision
	}{
		{"nothing synced", nil, "", DecisionOff},
		{"protection off", &State{Version: 2}, "", DecisionOff},
		{"on, no hash yet", &State{Enabled: true, Version: 1}, "", DecisionNoHash},
		{"exact token", on, exampleToken, DecisionMatch},
		{"typed loosely", on, strings.Repeat("kLmOp ", 6), DecisionMatch},
		{"no token", on, "", DecisionBlocked},
		{"separators only", on, " - - ", DecisionBlocked},
		{"wrong token", on, exampleToken[:len(exampleToken)-1] + "Q", DecisionBlocked},
		{"truncated token", on, exampleToken[:29], DecisionBlocked},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Check(c.state, c.token)
			if got != c.want {
				t.Fatalf("Check = %v (%d), want %d", got, got, c.want)
			}
			if got.Allowed() != (c.want != DecisionBlocked) {
				t.Fatalf("Allowed = %t", got.Allowed())
			}
			if c.token != "" && strings.Contains(got.String(), c.token) {
				t.Fatal("the decision's message contains the token")
			}
		})
	}
}

func TestSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), StateFileName)
	if s, err := Load(path); s != nil || err != nil {
		t.Fatalf("Load of a missing file = %v, %v", s, err)
	}
	want := *enabledState(t)
	if err := Save(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || got == nil || *got != want {
		t.Fatalf("Load = %+v, %v; want %+v", got, err, want)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v, want 0600", fi.Mode().Perm())
		}
	}
	if d, err := CheckFile(path, exampleToken); err != nil || d != DecisionMatch {
		t.Fatalf("CheckFile = %v, %v", d, err)
	}
	if d, err := CheckFile(path, "wrong"); err != nil || d != DecisionBlocked {
		t.Fatalf("CheckFile(wrong) = %v, %v", d, err)
	}
}

func TestLoadRejectsMalformed(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"json":  "{",
		"salt":  `{"enabled":true,"version":1,"salt":"zz","token_hash":"` + strings.Repeat("a", 64) + `"}`,
		"hash":  `{"enabled":true,"version":1,"salt":"` + exampleSalt + `","token_hash":"abcd"}`,
		"short": `{"enabled":true,"version":1,"salt":"abcd","token_hash":"` + strings.Repeat("a", 64) + `"}`,
	} {
		path := filepath.Join(dir, name+".json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("%s: Load accepted %s", name, body)
		}
		// An unreadable file fails open, like no sync at all.
		if d, err := CheckFile(path, ""); err == nil || d != DecisionOff {
			t.Errorf("%s: CheckFile = %v, %v; want DecisionOff and an error", name, d, err)
		}
	}
}

type fakeRPC struct {
	answers []any // a string (JSON body) or an error, one per call
	calls   int
	fn      string
	params  string
}

func (f *fakeRPC) RPC(_ context.Context, fn string, params, out any, _ ...supabase.CallOption) error {
	f.fn = fn
	b, _ := json.Marshal(params)
	f.params = string(b)
	a := f.answers[f.calls]
	f.calls++
	if err, ok := a.(error); ok {
		return err
	}
	return json.Unmarshal([]byte(a.(string)), out)
}

func newTestSyncer(t *testing.T, f *fakeRPC) (*Syncer, string, *time.Time) {
	t.Helper()
	path := filepath.Join(t.TempDir(), StateFileName)
	s := NewSyncer(func() RPC { return f }, nil, path)
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	return s, path, &now
}

func TestSyncStoresAndReplaces(t *testing.T) {
	h := hashOf(t, exampleSalt, exampleCanonical)
	f := &fakeRPC{answers: []any{
		`{"enabled":true,"version":3,"salt":"` + exampleSalt + `","token_hash":"` + h + `"}`,
		// Switched off: the hash must not linger.
		`{"enabled":false,"version":4,"salt":null,"token_hash":null}`,
	}}
	s, path, _ := newTestSyncer(t, f)
	ctx := context.Background()

	if err := s.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if f.fn != RPCName || f.params != "{}" {
		t.Fatalf("called %s with %s, want %s with {}", f.fn, f.params, RPCName)
	}
	if d, _ := CheckFile(path, exampleToken); d != DecisionMatch {
		t.Fatalf("after the first sync: %v", d)
	}
	if err := s.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil || got == nil {
		t.Fatal(got, err)
	}
	if *got != (State{Version: 4}) {
		t.Fatalf("after switching off: %+v", *got)
	}
	if d, _ := CheckFile(path, ""); d != DecisionOff {
		t.Fatalf("after switching off: %v", d)
	}
}

func TestSyncRejectsMalformedAnswer(t *testing.T) {
	f := &fakeRPC{answers: []any{
		`{"enabled":true,"version":3,"salt":"` + exampleSalt + `","token_hash":"nothex"}`,
	}}
	s, path, _ := newTestSyncer(t, f)
	if err := s.Tick(context.Background()); err == nil {
		t.Fatal("a malformed hash was accepted")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state written for a malformed answer: %v", err)
	}
}

func TestSyncTransientErrorRetriesNextTick(t *testing.T) {
	f := &fakeRPC{answers: []any{
		&supabase.APIError{Status: 503},
		`{"enabled":false,"version":1,"salt":null,"token_hash":null}`,
	}}
	s, _, _ := newTestSyncer(t, f)
	if err := s.Tick(context.Background()); err == nil {
		t.Fatal("a 503 was not reported")
	}
	if err := s.Tick(context.Background()); err != nil || f.calls != 2 {
		t.Fatalf("second tick: %v after %d calls", err, f.calls)
	}
}

func TestSyncPermanentErrorsBackOff(t *testing.T) {
	for name, e := range map[string]error{
		"revoked (42501)":      &supabase.APIError{Status: 403, Code: "42501"},
		"not an agent":         &supabase.APIError{Status: 400, Code: "P0002"},
		"no RPC on the server": &supabase.APIError{Status: 404, Code: "PGRST202"},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeRPC{answers: []any{e, `{"enabled":false,"version":1,"salt":null,"token_hash":null}`}}
			s, _, now := newTestSyncer(t, f)
			ctx := context.Background()
			if err := s.Tick(ctx); err != nil {
				t.Fatalf("a permanent error failed the task: %v", err)
			}
			*now = now.Add(TickInterval)
			if err := s.Tick(ctx); err != nil || f.calls != 1 {
				t.Fatalf("polled again within the backoff: %v, %d calls", err, f.calls)
			}
			*now = now.Add(permanentBackoff)
			if err := s.Tick(ctx); err != nil || f.calls != 2 {
				t.Fatalf("after the backoff: %v, %d calls", err, f.calls)
			}
		})
	}
}

func TestSyncUsesRetrier(t *testing.T) {
	f := &fakeRPC{answers: []any{`{"enabled":false,"version":1,"salt":null,"token_hash":null}`}}
	path := filepath.Join(t.TempDir(), StateFileName)
	used := false
	s := NewSyncer(func() RPC { return f }, func(_ context.Context, fn func() error) error {
		used = true
		return fn()
	}, path)
	if err := s.Tick(context.Background()); err != nil || !used {
		t.Fatalf("Tick = %v, retrier used = %t", err, used)
	}
}
