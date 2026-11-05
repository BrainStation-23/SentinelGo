//go:build !windows

package localadmin

import (
	"context"
	"errors"
)

// signOutWindows is only used on Windows; tests on other hosts replace it.
func signOutWindows(context.Context, string) (int, error) {
	return 0, errors.New("signing out Windows sessions is only possible on Windows")
}
