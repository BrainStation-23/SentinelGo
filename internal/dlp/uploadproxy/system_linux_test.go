package uploadproxy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxTruster(t *testing.T) {
	dir := t.TempDir()
	updates := 0
	prevDir, prevUpdate := anchorDir, updateCABundle
	anchorDir, updateCABundle = dir, func() error { updates++; return nil }
	t.Cleanup(func() { anchorDir, updateCABundle = prevDir, prevUpdate })
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tr := NewTruster()
	if err := tr.Trust(ca); err != nil {
		t.Fatal(err)
	}
	if err := tr.Trust(ca); err != nil { // unchanged: no second update
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, anchorName))
	if err != nil || string(b) != string(ca.CertPEM()) || updates != 1 {
		t.Errorf("anchor %v, %d updates", err, updates)
	}
	if err := tr.Untrust(); err != nil || updates != 2 {
		t.Errorf("untrust %v, %d updates", err, updates)
	}
	if err := tr.Untrust(); err != nil || updates != 2 {
		t.Errorf("untrust again %v, %d updates", err, updates)
	}
	anchorDir = filepath.Join(dir, "missing")
	if err := tr.Trust(ca); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("no anchor dir: %v", err)
	}
	if err := NewRedirector("").Apply("x"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("redirect: %v", err)
	}
}
