package software

import "sentinelgo/internal/userhomes"

// userHomeDirs returns the home directories of every real user on the machine
// (see userhomes.Dirs). It is a package var so tests can substitute a
// deterministic single-home list.
var userHomeDirs = userhomes.Dirs
