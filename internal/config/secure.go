package config

// SecureFile locks a secret-bearing file in the config directory down like
// config.json: SYSTEM, Administrators and the running account on Windows,
// 0600 elsewhere. The first-boot enrollment token file uses it (#358).
func SecureFile(path string) error { return secureConfigFile(path) }
