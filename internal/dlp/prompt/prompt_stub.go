//go:build !windows && !darwin && !linux

package prompt

import "context"

// Show can't ask on this platform.
func Show(context.Context, Ask) (Answer, error) { return Answer{}, ErrUnavailable }
