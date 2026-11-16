package walk

import (
	"errors"
	"io/fs"

	"sentinelgo/internal/yara"
)

// ErrorReason classifies an error opening or reading a file for the scan
// summary's errors_by_reason: access_denied, locked (in use, sharing
// violation) or read_error.
func ErrorReason(err error) string {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return yara.ErrAccessDenied
	case lockedErr(err):
		return yara.ErrLocked
	}
	return yara.ErrRead
}

// ErrorDetail is the OS error text for a problem file: the innermost error
// of a *fs.PathError, so the path itself (which hashed path mode must not
// send) is left out. At most yara.MaxProblemDetail bytes.
func ErrorDetail(err error) string {
	if err == nil {
		return ""
	}
	var pe *fs.PathError
	if errors.As(err, &pe) && pe.Err != nil {
		err = pe.Err
	}
	return yara.Truncate(err.Error(), yara.MaxProblemDetail)
}
