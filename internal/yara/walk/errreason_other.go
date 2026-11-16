//go:build !windows

package walk

import (
	"errors"
	"syscall"
)

// lockedErr: the file is busy (a mandatory lock, or a running executable
// opened for writing).
func lockedErr(err error) bool {
	return errors.Is(err, syscall.EBUSY) || errors.Is(err, syscall.ETXTBSY) || errors.Is(err, syscall.EAGAIN)
}
