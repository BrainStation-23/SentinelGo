package software

// Test hooks for the external software_test package.
//
// The dedupe and cadence state is process-global by design — one agent, one
// software pipeline — so tests that exercise consecutive cycles need a way to
// start from a known point, and tests of the fingerprint need to reach it
// without making it part of the package's real API.

// ResetSyncState clears the package-level dedupe and cadence state.
var ResetSyncState = resetSyncState

// HashSoftwareSnapshot exposes the dedupe fingerprint for testing.
var HashSoftwareSnapshot = hashSoftwareSnapshot
