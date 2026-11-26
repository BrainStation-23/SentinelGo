// Package uninstallprotect is the agent half of the uninstall token (#566,
// backend contract: sentinel-ops docs/agent-uninstall-token.md).
//
// Removing the agent through its own uninstall paths (`msiexec /x` on the
// MSI, `sentinelgo -uninstall`) needs a per-device token that only the
// console holds. The agent never holds the token: a scheduler task syncs
// {enabled, version, salt, token_hash} from agent_get_uninstall_protection
// into StateFileName, and `sentinelgo uninstall-check` hashes what the admin
// typed and compares.
//
// This is a deterrent, not tamper protection. Without a kernel driver an
// administrator can still `sc stop` / `sc delete` the service and delete the
// files.
package uninstallprotect

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"sentinelgo/internal/atomicfile"
	"sentinelgo/internal/winsec"
)

// StateFileName is the synced protection state, next to config.json. It
// holds the salt and the token's hash, never the token.
const StateFileName = "uninstall_protection.json"

// Sizes from the contract: a 16-byte salt and a SHA-256 hash, both hex.
const (
	saltBytes = 16
	hashBytes = 32
)

// State is the server's answer, as stored on the device.
type State struct {
	Enabled   bool   `json:"enabled"`
	Version   int64  `json:"version"`
	Salt      string `json:"salt,omitempty"`
	TokenHash string `json:"token_hash,omitempty"`
}

// validate checks the salt and hash of an enabled state. An enabled state
// without a hash is valid: the contract lets the uninstall through until one
// syncs.
func (s State) validate() error {
	if !s.Enabled || (s.Salt == "" && s.TokenHash == "") {
		return nil
	}
	if b, err := hex.DecodeString(s.Salt); err != nil || len(b) != saltBytes {
		return errors.New("salt is not 16 bytes of hex")
	}
	if b, err := hex.DecodeString(s.TokenHash); err != nil || len(b) != hashBytes {
		return errors.New("token_hash is not a hex SHA-256")
	}
	return nil
}

// StatePath is StateFileName in the directory of the config file.
func StatePath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), StateFileName)
}

// Load reads the state file. A missing file is (nil, nil): nothing has synced.
func Load(path string) (*State, error) {
	data, err := os.ReadFile(path) // #nosec G304 - the agent's own state file in its config directory
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return &s, nil
}

// Save writes the state atomically, secured like config.json: 0600 on Unix,
// SYSTEM and Administrators only on Windows. An unchanged state isn't
// rewritten.
func Save(path string, s State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, data) { // #nosec G304 - see Load
		return nil
	}
	if err := atomicfile.Write(path, data, 0o600); err != nil {
		return err
	}
	if err := winsec.SecurePath(path); err != nil {
		log.Printf("Uninstall protection: could not restrict access to %s: %v", path, err)
	}
	return nil
}
