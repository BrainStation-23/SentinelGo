//go:build linux

package security

// Fuzz target for the sshd config parsers (#250). They read `sshd -T`
// output and the sshd_config files, which an admin or a package can shape,
// so parsing them must never panic on unexpected input.
//
// The seed corpus runs as an ordinary unit test under `go test ./...`.
// To fuzz: go test -run='^$' -fuzz='^FuzzSSHConfigParsers$' -fuzztime=1m ./internal/osinfo/security/

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzSSHConfigParsers(f *testing.F) {
	for _, s := range []string{
		"", "\n", "#", "Match", "Include", "Include \"", "Include /", "Include ../../../etc/passwd",
		"Include sshd_config\nPasswordAuthentication no\n",
		"permitrootlogin yes\npasswordauthentication no\npubkeyauthentication yes\n",
		"PermitRootLogin without-password\nMatch User x\nPermitRootLogin yes\n",
		"Include \"sshd_config.d/*.conf\" [\nPubkeyAuthentication maybe\n",
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, s string) {
		_, _ = parseSSHEffectiveConfig(s)
		_, _, _ = parseSSHConfigData(s)

		root := t.TempDir()
		dir := filepath.Join(root, "etc", "ssh")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "sshd_config"), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		orig := securityHostRoot
		defer func() { securityHostRoot = orig }()
		securityHostRoot = root
		var lines []string
		_ = readSSHGlobalConfig(filepath.Join(dir, "sshd_config"), 0, &lines)
	})
}
