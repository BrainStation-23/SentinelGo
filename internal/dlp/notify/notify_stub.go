//go:build !windows && !darwin && !linux

package notify

import "errors"

func platformSend(string, string) error { return errors.New("notifications are not supported here") }
