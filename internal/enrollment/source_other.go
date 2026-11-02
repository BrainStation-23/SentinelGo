//go:build !darwin

package enrollment

// TokenMayArriveLater: here an installer writes the token file before the
// agent first starts, so no token means a broken install, not a wait.
const TokenMayArriveLater = false

// platformSource: only the token file next to config.json on this platform.
func platformSource() (Source, error) { return Source{}, ErrNoToken }
