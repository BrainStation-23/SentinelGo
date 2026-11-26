package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	"sentinelgo/internal/uninstallprotect"
)

// testUninstallToken has the contract's shape; deliberately repetitive, so
// secret scanners don't take it for a real credential.
var testUninstallToken = strings.TrimSuffix(strings.Repeat("K1M0P-", 6), "-")

// protectedConfig writes an enabled uninstall protection state next to a
// config path in a temp dir and returns that config path.
func protectedConfig(t *testing.T, s *uninstallprotect.State) string {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "config.json")
	if s != nil {
		if err := uninstallprotect.Save(uninstallprotect.StatePath(cfg), *s); err != nil {
			t.Fatal(err)
		}
	}
	return cfg
}

func enabledUninstallState() *uninstallprotect.State {
	salt := strings.Repeat("a5", 16)
	b, _ := hex.DecodeString(salt)
	sum := sha256.Sum256(append(b, strings.Repeat("K1M0P", 6)...))
	return &uninstallprotect.State{Enabled: true, Version: 3, Salt: salt, TokenHash: hex.EncodeToString(sum[:])}
}

func TestRunUninstallCheck(t *testing.T) {
	on := enabledUninstallState()
	cases := []struct {
		name  string
		state *uninstallprotect.State
		args  []string
		stdin string
		want  int
	}{
		{"nothing synced", nil, []string{"-token", ""}, "", 0},
		{"protection off", &uninstallprotect.State{Version: 2}, []string{"-token", ""}, "", 0},
		{"on, no hash yet", &uninstallprotect.State{Enabled: true, Version: 1}, nil, "", 0},
		{"right token", on, []string{"-token", testUninstallToken}, "", 0},
		{"right token, lower case", on, []string{"-token", strings.ToLower(testUninstallToken)}, "", 0},
		{"token on stdin", on, []string{"-token", "-"}, testUninstallToken + "\r\n", 0},
		{"no token (empty MSI property)", on, []string{"-token", ""}, "", 1},
		{"wrong token", on, []string{"-token", strings.Repeat("A", 30)}, "", 1},
		{"empty stdin", on, []string{"-token", "-"}, "", 2},
		{"unknown flag", on, []string{"-bogus"}, "", 2},
		{"stray argument", on, []string{"extra"}, "", 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := protectedConfig(t, c.state)
			var out, errOut bytes.Buffer
			args := append([]string{"-config", cfg}, c.args...)
			got := RunUninstallCheck(args, strings.NewReader(c.stdin), &out, &errOut)
			if got != c.want {
				t.Fatalf("exit %d, want %d (stdout %q, stderr %q)", got, c.want, out.String(), errOut.String())
			}
			all := strings.ToUpper(out.String() + errOut.String())
			if strings.Contains(all, "K1M0P") {
				t.Fatalf("the token was printed: %q", all)
			}
		})
	}
}
