package detect

import (
	"math/rand/v2"
	"strings"
)

// Secret fixtures are generated at test time from a fixed seed, so they are
// obviously fake and no secret-shaped literal sits in the repository (where
// push protection and secret scanners would flag it).

const (
	upper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lower  = "abcdefghijklmnopqrstuvwxyz"
	digits = "0123456789"
	alnum  = upper + lower + digits
	b32    = upper + "234567"
	b64    = alnum + "+/"
)

// fake returns n characters from alphabet, deterministic for seed.
func fake(seed uint64, alphabet string, n int) string {
	r := rand.New(rand.NewPCG(seed, seed^0x5eed))
	var b strings.Builder
	for range n {
		b.WriteByte(alphabet[r.IntN(len(alphabet))])
	}
	return b.String()
}

// secretSamples maps a description to (text containing a fake secret, the
// detector expected to flag it).
func secretSamples() []struct{ name, text, want string } {
	pemHeader := "-----BEGIN " + "RSA PRIVATE" + " KEY-----"
	pemFooter := "-----END " + "RSA PRIVATE" + " KEY-----"
	var pem strings.Builder
	pem.WriteString(pemHeader + "\n")
	for i := range 6 {
		pem.WriteString(fake(uint64(100+i), b64, 64) + "\n")
	}
	pem.WriteString(pemFooter)

	return []struct{ name, text, want string }{
		{"aws access key", "export AWS_ACCESS_KEY_ID=" + "AK" + "IA" + fake(1, b32, 16), "secrets.aws-access-token"},
		{"aws secret key", "aws_secret_access_key = " + fake(2, b64, 40), "secrets.aws-secret-access-key"},
		{"github pat", "token: " + "gh" + "p_" + fake(3, alnum, 36), "secrets.github-pat"},
		{"gitlab pat", "glp" + "at-" + fake(4, alnum, 20), "secrets.gitlab-pat"},
		{"slack bot token", "xo" + "xb-" + fake(5, digits, 12) + "-" + fake(6, digits, 12) + "-" + fake(7, alnum, 24), "secrets.slack-bot-token"},
		{"stripe live key", "STRIPE_KEY=" + "sk" + "_live_" + fake(8, alnum, 24), "secrets.stripe-access-token"},
		{"private key", pem.String(), "secrets.private-key"},
		{"jwt", "Authorization: Bearer " + "ey" + "J" + fake(9, alnum, 30) + ".eyJ" + fake(10, alnum, 40) + "." + fake(11, alnum, 43) + " ", "secrets.jwt"},
	}
}

// clipboardFalsePositives is everyday clipboard content that must not match
// any default detector (secrets.all plus the default PII set).
var clipboardFalsePositives = []string{
	"550e8400-e29b-41d4-a716-446655440000",
	"commit 9fceb02d0ae598e95dc970b74767f19372d61af8",
	"sha256:3a8f2c1b9d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a",
	"github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=",
	"luhn-invalid 4111111111111112",
	"v1.2.3 v10.20.30-rc.1 1.0.0.12345",
	"revenue grew 12.5% to $4,300,000 in Q3 2026, order #1234567890123",
	"https://example.com/search?q=go&page=2&id=1234567890",
	"timestamp 1730123456789 port 8080 pid 41234",
	`secret := os.Getenv("AWS_SECRET_ACCESS_KEY")`,
	`password: ${DB_PASSWORD}`,
	`api_key = "{{ .Values.apiKey }}"`,
	"token=<YOUR_TOKEN_HERE>",
	"export AWS_ACCESS_KEY_ID=" + "AK" + "IAIOSFODNN7" + "EXAMPLE",
	"Meeting moved to 3pm, room 4.12. Call me on Teams.",
	"SELECT id, name FROM users WHERE created_at > now() - interval '7 days';",
	"func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {",
	"C:\\Users\\alice\\AppData\\Local\\Temp\\report-2026-10-28.xlsx",
	"bad iban GB82WEST12345698765433",
	"ssn 000-12-3456",
}
