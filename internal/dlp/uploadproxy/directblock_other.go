//go:build !linux && !(windows && (amd64 || arm64))

package uploadproxy

import "net"

// platformDirectBlocker is nil: blocking direct connections needs WFP
// (Windows) or nftables (Linux); on macOS, filtering by app would need a
// Network Extension, which the agent doesn't ship.
var platformDirectBlocker func(RedirectPorts) (DirectBlocker, error)

// platformResolver isn't used without a blocker.
var platformResolver Resolver

// platformDirectCleanup: nothing outlives the agent here.
var platformDirectCleanup func() error

// platformTransparent: no transparent redirect here.
var platformTransparent func() ([]net.Listener, RedirectPorts, OriginalDst, error)
