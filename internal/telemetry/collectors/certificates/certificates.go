// Package certificates implements the telemetry Certificates collector,
// filling the "certificates" section: trusted-root and system certificate
// inventory.
//
// Every field is exactly what docs/telemetry/03-collection-matrix.md
// specifies and nothing more: "subject, issuer, thumbprint, validity dates
// and key usage only — never private keys." No platform mechanism this
// collector uses (the Windows Cert: PSDrive, crypto/x509 parsing of PEM
// files, `security find-certificate -p`) ever touches key material, so this
// is a structural guarantee, not a filter applied after the fact.
//
// Payload is a bare slice, not a struct wrapping one: SectionCertificates is
// registered Chunked in section.go, and telemetry.ChunkSection requires the
// value Collect returns to reflect as a slice directly (see chunk.go and the
// patches collector, which established this pattern first).
package certificates

import (
	"context"
	"sort"

	tel "sentinelgo/internal/telemetry"
)

// Name is the collector's identifier, also used as its section name.
const Name = tel.SectionCertificates

// Certificate describes one certificate found in a trusted store.
type Certificate struct {
	Subject string `json:"subject,omitempty"`
	Issuer  string `json:"issuer,omitempty"`
	// Thumbprint is the certificate's SHA-1 fingerprint, hex-encoded — the
	// identifier every platform's own cert tooling uses to refer to a
	// specific certificate.
	Thumbprint string `json:"thumbprint,omitempty"`
	NotBefore  string `json:"not_before,omitempty"`
	NotAfter   string `json:"not_after,omitempty"`
	// Store is the trust store this certificate was found in: "root"/"my"
	// on Windows, the source file path on Linux, "system"/"login" on macOS.
	Store string `json:"store,omitempty"`
}

// Payload is the wire shape of the "certificates" section — see the package
// doc for why this is a bare slice rather than a struct.
type Payload []Certificate

// Collector implements telemetry.Collector for certificate inventory.
type Collector struct{}

// New returns the Certificates collector.
func New() *Collector { return &Collector{} }

func (c *Collector) Name() string       { return Name }
func (c *Collector) Section() string    { return tel.SectionCertificates }
func (c *Collector) SchemaVersion() int { return 1 }

// Capability reports certificate inventory as always supported: every
// platform ships a queryable trust store.
func (c *Collector) Capability(context.Context, tel.CollectorConfig) (string, tel.CapabilityState) {
	return tel.CapKeyCertificates, tel.CapSupported
}

// Collect gathers certificate inventory.
func (c *Collector) Collect(ctx context.Context, cfg tel.CollectorConfig) (any, tel.CollectorResult) {
	res, done := tel.NewResult(c.Name(), c.Section())

	sig := platformCertificates(ctx)
	for _, w := range sig.Warnings {
		res.AddWarning(w)
	}

	sortCertificates(sig.Certificates)
	certs := sig.Certificates
	if cfg.MaxItems > 0 && len(certs) > cfg.MaxItems {
		certs = certs[:cfg.MaxItems]
	}

	return Payload(certs), *done(sig.Err, sig.Source, len(certs))
}

// signal is what platform code supplies before assembling Payload.
type signal struct {
	Certificates []Certificate
	Err          error
	Source       string
	Warnings     []string
}

// sortCertificates orders the list deterministically by thumbprint, so an
// unchanged certificate set hashes identically cycle to cycle —
// Fingerprint's documented requirement for any list payload.
func sortCertificates(c []Certificate) {
	sort.Slice(c, func(i, j int) bool { return c[i].Thumbprint < c[j].Thumbprint })
}
