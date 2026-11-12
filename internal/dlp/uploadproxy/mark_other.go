//go:build !linux

package uploadproxy

import "syscall"

// setMark does nothing: only the Linux backstop redirects by firewall rule.
func setMark(syscall.RawConn, uint32) {}
