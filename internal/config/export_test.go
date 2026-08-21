package config

import "testing"

// SetDefaultConfigPathForTest redirects the empty-path branch of Load at path
// for the duration of one test, restoring the real resolver afterwards.
//
// This file is compiled only under `go test`, so the production binary has no
// way to reach it: the seam exists for hermeticity, not configurability. Tests
// that exercise Load("") must use it — without it they create, harden and read
// the live agent config directory on whatever machine the suite runs on.
func SetDefaultConfigPathForTest(t *testing.T, path string) {
	t.Helper()

	previous := defaultConfigPath
	defaultConfigPath = func() string { return path }
	t.Cleanup(func() { defaultConfigPath = previous })
}

// RealDefaultConfigPath exposes the unpatched resolver so a test can assert the
// shape of the production path without triggering any of Load's side effects.
func RealDefaultConfigPath() string { return GetDefaultConfigPath() }
