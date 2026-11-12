package native

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"sentinelgo/internal/adminpassword"
	"sentinelgo/internal/config"
	"sentinelgo/internal/taskstore"
)

// AdminPasswordRotator polls the admin password policy now and rotates if
// due (#361); the service installs it on Windows (adminpassword.Rotator).
type AdminPasswordRotator func(ctx context.Context) (adminpassword.TaskResult, error)

var (
	adminPasswordMu      sync.RWMutex
	adminPasswordRotator AdminPasswordRotator
)

// SetAdminPasswordRotator installs (or with nil removes) what
// admin-password-rotate calls.
func SetAdminPasswordRotator(f AdminPasswordRotator) {
	adminPasswordMu.Lock()
	defer adminPasswordMu.Unlock()
	adminPasswordRotator = f
}

var errAdminPasswordOff = errors.New("local admin password rotation is not running in this agent process (Windows only)")

// adminPasswordRotateHandler is the admin-password-rotate task (contract
// §4): the console's Rotate now, and the nudge after a reveal. The note
// never carries the password.
type adminPasswordRotateHandler struct{}

func init() { Register(&adminPasswordRotateHandler{}) }

func (h *adminPasswordRotateHandler) Slugs() []string {
	return []string{adminpassword.TaskRotate}
}

func (h *adminPasswordRotateHandler) Run(ctx context.Context, _ *config.Config, _ taskstore.Task) (string, error) {
	adminPasswordMu.RLock()
	f := adminPasswordRotator
	adminPasswordMu.RUnlock()
	if f == nil {
		return "", errAdminPasswordOff
	}
	res, err := f(ctx)
	if err != nil {
		return "", fmt.Errorf("%s: %w", adminpassword.TaskRotate, err)
	}
	var msg string
	switch {
	case res.Rotated && res.ErrorCode == "":
		msg = "local admin password rotated and escrowed"
	case res.Rotated:
		msg = "local admin password rotated; confirming it to the server failed and is retried"
	case res.State == adminpassword.StateActive:
		msg = "no rotation due"
	case res.State == adminpassword.StateUnavailable:
		msg = "the server doesn't offer admin password rotation yet"
	case res.ErrorCode != "":
		msg = "local admin password not rotated: " + res.ErrorCode
	default:
		msg = "local admin password not rotated: " + res.State
	}
	note := resultNote(msg, res)
	if res.ErrorCode != "" && !res.Rotated {
		return "", errors.New(note)
	}
	return note, nil
}
