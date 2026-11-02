// Package uploadproxy is file DLP's upload channel (#344, phase 1): a local
// HTTPS proxy that decrypts uploads to the destinations in scope, has each
// uploaded file scanned by the sandboxed scan workers, and forwards or
// refuses the request. Everything outside the scope is tunnelled untouched.
//
// Phase 1 is the explicit proxy: clients are pointed at it (system proxy or
// PAC). Redirecting traffic transparently (WFP, nftables, a Network
// Extension) comes later.
//
// Security: the inspection CA is generated on the device and its key never
// leaves it (a root-only file). Upstream servers are verified against the
// system roots like any client would; verification is never skipped. Request
// bodies, URLs and file contents are never logged: only hosts and verdicts.
package uploadproxy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"sentinelgo/internal/winsec"
)

// CA file names in the agent's config directory.
const (
	CACertFile = "upload-proxy-ca.crt"
	CAKeyFile  = "upload-proxy-ca.key"
)

// Lifetimes: the CA is renewed this long before it expires, and host
// certificates are short-lived so a leaked one is useless soon.
const (
	caLifetime   = 2 * 365 * 24 * time.Hour
	caRenewAhead = 30 * 24 * time.Hour
	leafLifetime = 24 * time.Hour
	leafCacheMax = 1024
)

// CA is the device's inspection CA. It is safe for concurrent use.
type CA struct {
	cert    *x509.Certificate
	key     crypto.Signer
	certPEM []byte
	now     func() time.Time

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

// LoadOrCreateCA loads the CA from dir, or creates one (and writes it, the
// key readable by the owner only) when there is none or it is about to
// expire. dir is the agent's root-only config directory.
func LoadOrCreateCA(dir string) (*CA, error) {
	return loadOrCreateCA(dir, time.Now)
}

func loadOrCreateCA(dir string, now func() time.Time) (*CA, error) {
	certPath, keyPath := filepath.Join(dir, CACertFile), filepath.Join(dir, CAKeyFile)
	if ca, err := loadCA(certPath, keyPath, now); err == nil {
		if now().Add(caRenewAhead).Before(ca.cert.NotAfter) {
			return ca, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ca, err := newCA(now)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.key)
	if err != nil {
		return nil, err
	}
	if err := writeFileAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600, true); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(certPath, ca.certPEM, 0o644, false); err != nil {
		return nil, err
	}
	return ca, nil
}

func loadCA(certPath, keyPath string, now func() time.Time) (*CA, error) {
	certPEM, err := os.ReadFile(certPath) // #nosec G304 -- fixed name in the config directory
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath) // #nosec G304 -- fixed name in the config directory
	if err != nil {
		return nil, err
	}
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, fmt.Errorf("upload proxy CA: unreadable PEM in %s", filepath.Dir(certPath))
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("upload proxy CA: %w", err)
	}
	k, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("upload proxy CA key: %w", err)
	}
	signer, ok := k.(crypto.Signer)
	if !ok || !cert.IsCA {
		return nil, errors.New("upload proxy CA: not a CA certificate and signing key")
	}
	return &CA{cert: cert, key: signer, certPEM: certPEM, now: now, leaves: map[string]*tls.Certificate{}}, nil
}

func newCA(now func() time.Time) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	t := now()
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{Organization: []string{"SentinelOps"}, CommonName: "SentinelOps Upload Inspection CA (" + host + ")"},
		NotBefore:             t.Add(-time.Hour),
		NotAfter:              t.Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true, // signs host certificates only, never another CA
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		now: now, leaves: map[string]*tls.Certificate{}}, nil
}

func randomSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return big.NewInt(time.Now().UnixNano())
	}
	return n.Add(n, big.NewInt(1))
}

// CertPEM is the CA certificate, to install in the device's trust stores.
func (ca *CA) CertPEM() []byte { return append([]byte(nil), ca.certPEM...) }

// Certificate is the parsed CA certificate.
func (ca *CA) Certificate() *x509.Certificate { return ca.cert }

// Leaf returns a certificate for host signed by the CA, reusing one that is
// still valid for at least an hour.
func (ca *CA) Leaf(host string) (*tls.Certificate, error) {
	now := ca.now()
	ca.mu.Lock()
	if c, ok := ca.leaves[host]; ok && now.Add(time.Hour).Before(c.Leaf.NotAfter) {
		ca.mu.Unlock()
		return c, nil
	}
	ca.mu.Unlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(leafLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key, Leaf: leaf}
	ca.mu.Lock()
	if len(ca.leaves) >= leafCacheMax {
		ca.leaves = map[string]*tls.Certificate{}
	}
	ca.leaves[host] = c
	ca.mu.Unlock()
	return c, nil
}

// writeFileAtomic writes data to path with mode, through a temporary file in
// the same directory, so a crash never leaves a half-written key. A secret
// file is restricted before anything is written to it: mode on Unix, and on
// Windows (where modes don't apply) an ACL for SYSTEM, Administrators and the
// service's account only.
func writeFileAtomic(path string, data []byte, mode os.FileMode, secret bool) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if secret {
		if err := winsec.SecurePath(name); err != nil {
			_ = tmp.Close()
			return fmt.Errorf("restrict %s: %w", filepath.Base(path), err)
		}
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
