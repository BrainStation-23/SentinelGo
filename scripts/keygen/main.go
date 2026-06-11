// keygen generates a one-time ed25519 signing keypair for SentinelGo release artifacts.
// Run once locally, then discard — never commit the private key.
//
// Usage:
//
//	go run ./scripts/keygen
//
// Output:
//   - SENTINELGO_SIGNING_KEY  → add as a GitHub Actions secret (base64 private key)
//   - Public key base64       → save in Supabase for future task-script signing
//   - Go byte literal         → paste into internal/updater/pubkey.go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== SentinelGo ed25519 Signing Keypair ===")
	fmt.Println()
	fmt.Println("SENTINELGO_SIGNING_KEY (add to GitHub Actions secrets → never commit):")
	fmt.Println(base64.StdEncoding.EncodeToString(priv))
	fmt.Println()
	fmt.Println("Public key base64 (save in Supabase for future task-script signing):")
	fmt.Println(base64.StdEncoding.EncodeToString(pub))
	fmt.Println()
	fmt.Println("Go byte literal for internal/updater/pubkey.go:")
	fmt.Println("var PublicKey = ed25519.PublicKey{")
	fmt.Printf("\t")
	for i, b := range pub {
		fmt.Printf("0x%02x,", b)
		if i < len(pub)-1 {
			if (i+1)%8 == 0 {
				fmt.Printf("\n\t")
			} else {
				fmt.Printf(" ")
			}
		}
	}
	fmt.Println()
	fmt.Println("}")
}
