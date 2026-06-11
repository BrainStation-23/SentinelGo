//go:build windows

package config

import "sentinelgo/internal/winsec"

// secureConfigFile applies an explicit DACL to the config file so only SYSTEM,
// the local Administrators group, and the account running the agent can read or
// modify it.
//
// On Windows, Go's os.Chmod only toggles the read-only bit — it does NOT set a
// restrictive ACL. The config holds the agent's access token, refresh token and
// agent secret in cleartext; under the default ACL inherited from the drive
// root, the local Users group can read it. This locks it down explicitly.
func secureConfigFile(path string) error {
	return winsec.SecurePath(path)
}

// secureDir applies the same restrictive DACL to the directory holding the
// config so child items do not inherit broader permissions.
func secureDir(path string) error {
	return winsec.SecurePath(path)
}
