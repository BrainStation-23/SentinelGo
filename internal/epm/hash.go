package epm

import "sentinelgo/internal/hashutil"

// ComputeFileHash returns the lowercase hex-encoded SHA-256 digest of the file
// at path. Used for hash-based policy matching (PolicyRule.AppHash) — the
// same primitive internal/updater uses to verify release binaries.
//
// The implementation lives in internal/hashutil so that both this package and
// internal/service/software can use it without creating an import cycle.
func ComputeFileHash(path string) (string, error) {
	return hashutil.ComputeFileHash(path)
}
