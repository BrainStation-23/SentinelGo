package walk

import (
	"errors"

	"golang.org/x/sys/windows"
)

// lockedErr: another process holds the file open without sharing, or has
// locked the range read.
func lockedErr(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}
