// Package atomicfile writes a file so that readers see either the old or the
// new content, never a partial write.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write writes data to a temp file next to path with mode perm, flushes it to
// disk and renames it over path. On failure the temp file is removed and path
// is left as it was.
func Write(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(perm)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmpPath, path)
	}
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return nil
}
