package walk

import "errors"

// ErrChanged is returned by Open when the path no longer names the file the
// walk listed (replaced by a link, a folder or another file).
var ErrChanged = errors.New("walk: file changed since it was listed")
