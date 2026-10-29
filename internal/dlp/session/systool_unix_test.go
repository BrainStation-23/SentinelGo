//go:build linux || darwin

package session

import (
	"path/filepath"
	"testing"
)

func TestSysTool(t *testing.T) {
	p, err := sysTool("sh")
	if err != nil || !filepath.IsAbs(p) {
		t.Errorf("sysTool(sh) = %q, %v; want an absolute system path", p, err)
	}
	if _, err := sysTool("definitely-not-a-sentinelgo-tool"); err == nil {
		t.Error("missing tool resolved")
	}
}
