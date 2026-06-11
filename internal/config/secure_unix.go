//go:build !windows

package config

import "os"

// secureConfigFile ensures the config file is owner-read/write only. On Unix the
// 0600 mode set when the file is written already enforces this; this re-asserts
// it defensively (e.g. if the file pre-existed with looser permissions).
func secureConfigFile(path string) error {
	return os.Chmod(path, 0600)
}

// secureDir ensures the directory is owner-only (0700) on Unix.
func secureDir(path string) error {
	return os.Chmod(path, 0700)
}
