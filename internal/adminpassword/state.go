package adminpassword

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// StateFileName is the rotator's state file in the config directory. It
// holds ids and times only, never a password.
const StateFileName = "admin_password_state.json"

// Pending is a rotation that was escrowed but not yet confirmed.
type Pending struct {
	RotationID string    `json:"rotation_id"`
	AccountSID string    `json:"account_sid"`
	Reason     string    `json:"reason"`
	StartedAt  time.Time `json:"started_at"`
}

// State is what survives a restart.
type State struct {
	LastRotationID string       `json:"last_rotation_id,omitempty"`
	LastRotatedAt  *time.Time   `json:"last_rotated_at,omitempty"`
	AccountSID     string       `json:"account_sid,omitempty"`
	Pending        *Pending     `json:"pending,omitempty"`
	LastError      *StatusError `json:"last_error,omitempty"`
	RetryAfter     *time.Time   `json:"retry_after,omitempty"`
}

func loadState(path string) (State, error) {
	var s State
	data, err := os.ReadFile(path) // #nosec G304 - path is the agent's own state file in its config directory
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return State{}, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return s, nil
}

func saveState(path string, s State) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// newRotationID returns a random (version 4) UUID.
func newRotationID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:], nil
}
