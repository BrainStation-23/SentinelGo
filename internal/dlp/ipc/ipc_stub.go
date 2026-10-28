//go:build !windows && !linux && !darwin

package ipc

import (
	"context"
	"errors"
	"runtime"
)

// DefaultAddress is unused on this platform.
const DefaultAddress = ""

var errUnsupported = errors.New("ipc: DLP session IPC is not supported on " + runtime.GOOS)

// ErrClosed is returned by Accept after Close.
var ErrClosed = errors.New("ipc: listener closed")

func Listen(string) (Listener, error)            { return nil, errUnsupported }
func Dial(context.Context, string) (Conn, error) { return nil, errUnsupported }
func PeerIdentity(Conn) (Identity, error)        { return Identity{}, errUnsupported }
func ServerIdentity(Conn) (Identity, error)      { return Identity{}, errUnsupported }
func IsPrivileged(Identity) bool                 { return false }
func SameUser(Identity) bool                     { return false }
