//go:build !windows

package updater

import "fmt"

// swapOutcome mirrors the Windows type so shared code compiles everywhere.
type swapOutcome int

const (
	swapDone swapOutcome = iota
	swapDeferred
)

// replaceRunningBinary is never called on Unix: there the binary is replaced by
// atomicReplace before restart, because a running executable can be renamed over
// freely. The stub exists so the restart path type-checks on every platform
// rather than hiding behind a runtime.GOOS branch.
func replaceRunningBinary(_, _ string) (swapOutcome, error) {
	return swapDone, fmt.Errorf("replaceRunningBinary is Windows-only; " +
		"Unix replaces the binary in place via atomicReplace")
}
