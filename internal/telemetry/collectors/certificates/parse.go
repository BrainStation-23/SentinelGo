package certificates

import (
	"crypto/sha1" //nolint:gosec // SHA-1 here is a certificate fingerprint identifier, not a security primitive — it's the same algorithm every platform's own cert tooling (certutil, openssl x509 -fingerprint) uses to name a cert, not something guarding data.
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"time"
)

// parsePEMCertificates extracts every "CERTIFICATE" PEM block from a text
// blob — one file's content on Linux, or `security find-certificate -a -p`'s
// entire concatenated output on macOS — converting each into the wire shape.
// A block that fails to parse as an X.509 certificate is skipped rather than
// failing the whole blob: one malformed entry in a 150+ certificate system
// bundle must not lose every other certificate.
func parsePEMCertificates(data []byte, store string) []Certificate {
	var certs []Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, certFromX509(cert, store))
	}
	return certs
}

// dedupeCertificates removes entries sharing a thumbprint, keeping the
// first. /etc/ssl/certs routinely contains the same certificate reachable
// through both an individual file and a hash-named symlink, and again inside
// a combined ca-certificates.crt bundle if present — without this, the
// section would report the same certificate two or three times over.
func dedupeCertificates(certs []Certificate) []Certificate {
	seen := make(map[string]bool, len(certs))
	out := make([]Certificate, 0, len(certs))
	for _, c := range certs {
		if c.Thumbprint == "" || seen[c.Thumbprint] {
			continue
		}
		seen[c.Thumbprint] = true
		out = append(out, c)
	}
	return out
}

// This file holds every platform's parsing/conversion as pure functions with
// no build tag, so it is unit tested on every host regardless of GOOS.

// certFromX509 converts a parsed certificate into the wire shape, computing
// the SHA-1 thumbprint every platform's own cert tooling uses to identify a
// specific certificate. Only subject, issuer, thumbprint and validity dates
// are read — see the package doc's guarantee that key material is never
// touched.
func certFromX509(cert *x509.Certificate, store string) Certificate {
	sum := sha1.Sum(cert.Raw) //nolint:gosec // fingerprint identifier, not a security primitive — see the import comment
	return Certificate{
		Subject:    cert.Subject.String(),
		Issuer:     cert.Issuer.String(),
		Thumbprint: strings.ToUpper(hex.EncodeToString(sum[:])),
		NotBefore:  cert.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:   cert.NotAfter.UTC().Format(time.RFC3339),
		Store:      store,
	}
}

// ── Windows: Get-ChildItem Cert:\ ───────────────────────────────────────────

type windowsCertRow struct {
	Subject    string `json:"Subject"`
	Issuer     string `json:"Issuer"`
	Thumbprint string `json:"Thumbprint"`
	NotBefore  string `json:"NotBefore"`
	NotAfter   string `json:"NotAfter"`
	Store      string `json:"Store"`
}

// parseWindowsCerts parses the Cert: PSDrive script's JSON. A single
// certificate serializes as a bare object rather than a one-element array,
// the same ambiguity handled throughout this codebase's other
// PowerShell-JSON call sites.
func parseWindowsCerts(output string) ([]windowsCertRow, error) {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil, nil
	}

	var rows []windowsCertRow
	if err := json.Unmarshal([]byte(output), &rows); err == nil {
		return rows, nil
	}

	var single windowsCertRow
	if err := json.Unmarshal([]byte(output), &single); err != nil {
		return nil, err
	}
	return []windowsCertRow{single}, nil
}

func (r windowsCertRow) toCertificate() Certificate {
	return Certificate{
		Subject:    r.Subject,
		Issuer:     r.Issuer,
		Thumbprint: strings.ToUpper(r.Thumbprint),
		NotBefore:  r.NotBefore,
		NotAfter:   r.NotAfter,
		Store:      r.Store,
	}
}
