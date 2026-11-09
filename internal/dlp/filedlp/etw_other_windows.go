//go:build windows && !(amd64 || arm64)

package filedlp

import "errors"

// etwAvailable is false on 32-bit Windows: the ETW calls pass 64-bit
// handles and keywords, which the plain syscall path doesn't split.
const etwAvailable = false

type fileOpen struct {
	pid  uint32
	path string
}

type etwSession struct{}

func startETW(func(fileOpen)) (*etwSession, error) {
	return nil, errors.New("file tracing needs 64-bit Windows")
}

func (*etwSession) stop()                        {}
func (*etwSession) stats() (events, lost uint64) { return 0, 0 }
