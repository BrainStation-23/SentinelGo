package filedlp

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"sentinelgo/internal/dlp/policy"
)

// QuarantineDir is where quarantined files go, in the config directory.
const QuarantineDir = "dlp-quarantine"

// Quarantine limits: the folder never grows past quarantineMaxBytes, and
// entries older than quarantineKeep are removed when a new one arrives.
const (
	quarantineMaxBytes = 1 << 30
	quarantineKeep     = 30 * 24 * time.Hour
)

// errFileChanged: the path no longer names the file that was scanned, so it
// is left alone.
var errFileChanged = errors.New("the file was replaced or removed after it was scanned")

// remediator quarantines or deletes files found to violate a policy after
// they were written (on_close_violation). Errors never carry the file's path
// (#341). How a file is checked and removed is per OS (sameFile,
// removeFile).
type remediator struct {
	dir string // the quarantine folder
	now func() time.Time
}

func (m *remediator) remediate(r Request, action string) error {
	if err := m.sameFile(r); err != nil {
		return err
	}
	if action == policy.ViolationQuarantine {
		if err := m.quarantine(r); err != nil {
			return err
		}
		// The copy is safe: now remove the original, checking again that the
		// path still names it.
		if err := m.sameFile(r); err != nil {
			return err
		}
	}
	return m.removeFile(r)
}

// quarantine copies the file, from the handle the hook already holds, into
// the root/SYSTEM-only quarantine folder.
func (m *remediator) quarantine(r Request) error {
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return fmt.Errorf("quarantine folder: %w", errnoOnly(err))
	}
	used := m.prune()
	if used+r.Ident.Size > quarantineMaxBytes {
		return errors.New("the quarantine folder is full")
	}
	name := fmt.Sprintf("%s-%d-%d-%s", m.now().UTC().Format("20060102T150405Z"), r.Ident.Dev, r.Ident.Ino, filepath.Base(r.Path))
	dst, err := os.OpenFile(filepath.Join(m.dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- our own folder; the base name only
	if err != nil {
		return fmt.Errorf("quarantine copy: %w", errnoOnly(err))
	}
	_, err = io.Copy(dst, io.NewSectionReader(r.File, 0, r.Ident.Size))
	if err == nil {
		err = dst.Sync()
	}
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(dst.Name())
		return fmt.Errorf("quarantine copy: %w", errnoOnly(err))
	}
	return nil
}

// prune removes entries older than quarantineKeep and returns the size of
// what is left.
func (m *remediator) prune() int64 {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return 0
	}
	var used int64
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		if m.now().Sub(fi.ModTime()) > quarantineKeep {
			_ = os.Remove(filepath.Join(m.dir, e.Name()))
			continue
		}
		used += fi.Size()
	}
	return used
}

// errnoOnly drops the path from a *PathError, keeping the reason.
func errnoOnly(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
