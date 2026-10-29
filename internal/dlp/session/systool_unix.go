//go:build linux || darwin

package session

import (
	"fmt"
	"os"
	"path/filepath"
)

// sysDirs are the only places system tools are taken from. The service runs
// as root: resolving a bare name through PATH would let a writable PATH
// entry run its own program as root.
var sysDirs = []string{"/usr/bin", "/bin", "/usr/sbin", "/sbin"}

// sysTool returns the absolute path of a system tool.
func sysTool(name string) (string, error) {
	for _, dir := range sysDirs {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found in %v", name, sysDirs)
}
