//go:build !linux && !darwin && !windows

package walk

import "os"

// Open opens f read-only.
func Open(f File) (*os.File, error) { return os.Open(f.Path) } // #nosec G304 -- a path the walk listed
