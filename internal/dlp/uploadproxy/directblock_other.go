//go:build !(windows && (amd64 || arm64))

package uploadproxy

// platformDirectBlocker is nil: blocking direct connections needs WFP
// (Windows). Linux gets an nft backstop (#426 step 2); on macOS, filtering
// by app would need a Network Extension, which the agent doesn't ship.
var platformDirectBlocker func() (DirectBlocker, error)

// platformResolver isn't used without a blocker.
var platformResolver Resolver
