// sign generates ed25519 .sig files and a SHA256SUMS file for SentinelGo release binaries.
// It is called by the release pipeline (CI and `make release`) after binaries are built.
//
// Usage:
//
//	SENTINELGO_SIGNING_KEY=<base64-private-key> go run ./scripts/sign <binary1> [binary2 ...]
//
// For each binary it writes {binary}.sig (base64-encoded 64-byte ed25519 signature).
// It also writes SHA256SUMS in the same directory as the first binary argument.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	keyB64 := os.Getenv("SENTINELGO_SIGNING_KEY")
	if keyB64 == "" {
		fmt.Fprintln(os.Stderr, "error: SENTINELGO_SIGNING_KEY env var is not set")
		os.Exit(1)
	}

	privBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(keyB64))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to base64-decode SENTINELGO_SIGNING_KEY: %v\n", err)
		os.Exit(1)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		fmt.Fprintf(os.Stderr, "error: signing key must be %d bytes, got %d\n",
			ed25519.PrivateKeySize, len(privBytes))
		os.Exit(1)
	}
	priv := ed25519.PrivateKey(privBytes)

	binaries := os.Args[1:]
	if len(binaries) == 0 {
		fmt.Fprintln(os.Stderr, "usage: sign <binary1> [binary2 ...]")
		os.Exit(1)
	}

	type entry struct{ name, sum string }
	sums := make([]entry, 0, len(binaries))

	for _, binPath := range binaries {
		data, err := os.ReadFile(binPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to read %s: %v\n", binPath, err)
			os.Exit(1)
		}

		// Sign
		sig := ed25519.Sign(priv, data)
		sigPath := binPath + ".sig"
		if err := os.WriteFile(sigPath, []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "error: failed to write %s: %v\n", sigPath, err)
			os.Exit(1)
		}
		fmt.Printf("signed   %s\n", filepath.Base(binPath))

		// SHA256
		sum := sha256.Sum256(data)
		sums = append(sums, entry{filepath.Base(binPath), fmt.Sprintf("%x", sum)})
	}

	// Write SHA256SUMS in the same directory as the first binary
	var sb strings.Builder
	for _, e := range sums {
		fmt.Fprintf(&sb, "%s  %s\n", e.sum, e.name)
	}
	sha256sumsPath := filepath.Join(filepath.Dir(binaries[0]), "SHA256SUMS")
	if err := os.WriteFile(sha256sumsPath, []byte(sb.String()), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error: failed to write SHA256SUMS: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote    %s\n", sha256sumsPath)
}
