package enrollment

import (
	"encoding/json"
	"errors"
	"os"

	"sentinelgo/internal/osinfo/shared"
)

// managedPrefs is where macOS puts the settings of a custom-settings profile
// for domain com.sentinelgo.agent. Only root (the MDM client) can write it.
// A var for tests.
var managedPrefs = "/Library/Managed Preferences/com.sentinelgo.agent.plist"

// TokenMayArriveLater: an MDM can install the package before the profile that
// carries the token, so with no token yet the agent waits for it.
const TokenMayArriveLater = true

// runCommand is shared.RunCommand; a var for tests.
var runCommand = shared.RunCommand

// platformSource reads the token from MDM managed preferences: keys
// EnrollmentToken, ServerURL and AnonKey.
func platformSource() (Source, error) {
	if _, err := os.Stat(managedPrefs); errors.Is(err, os.ErrNotExist) {
		return Source{}, ErrNoToken
	}
	out, err := runCommand("plutil", "-convert", "json", "-o", "-", managedPrefs)
	if err != nil {
		return Source{}, err
	}
	var p struct {
		Token     string `json:"EnrollmentToken"`
		ServerURL string `json:"ServerURL"`
		AnonKey   string `json:"AnonKey"`
	}
	if err := json.Unmarshal([]byte(out), &p); err != nil {
		return Source{}, err
	}
	if p.Token == "" {
		return Source{}, ErrNoToken
	}
	return validate(Source{Token: p.Token, ServerURL: p.ServerURL, AnonKey: p.AnonKey, Origin: "MDM managed preferences"})
}
