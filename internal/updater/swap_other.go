//go:build !windows

package updater

import (
	"log"
	"os"
	"os/exec"
	"runtime"
)

// restartPlatform hands control back to the service manager after the binary has
// already been replaced in place by atomicReplace.
//
// Unix needs no equivalent of the Windows rename dance: a running executable can
// be replaced directly, so by the time this is called the new binary is already
// on disk and the only task left is to exit in the way this platform's service
// manager expects.
//
// The Windows counterpart lives in swap_windows.go. Splitting them by build tag
// rather than branching on runtime.GOOS means each build compiles only the code
// it can actually execute -- and it removes a stub that could never return a nil
// error, which staticcheck correctly read as an unreachable error path.
func restartPlatform(_, selfPath string) error {
	if runtime.GOOS == "darwin" {
		log.Println("Updater: update applied; exiting for launchd (KeepAlive) to relaunch the new binary")
		// Re-sign and re-register with Gatekeeper before exit. spctl --add stores
		// the binary's CDHash in the policy DB; after atomicReplace the CDHash has
		// changed, so the old install-time entry no longer matches. Without this,
		// launchd relaunches the new binary but Gatekeeper rejects it and the
		// daemon silently never comes back up.
		recodesignForGatekeeper(selfPath)
		os.Exit(0)
		return nil
	}

	// Linux and other systemd-managed platforms: a non-zero exit triggers
	// Restart=on-failure, relaunching the replaced binary.
	log.Println("Updater: update applied; exiting for systemd (Restart=on-failure) to relaunch the new binary")
	os.Exit(1)
	return nil
}

// recodesignForGatekeeper re-signs the binary with an ad-hoc identity and
// registers its new CDHash with Gatekeeper. Must be called after every atomic
// replace on macOS: spctl --add stores the CDHash at install time, and the
// replaced binary has a completely different hash, so without this launchd
// cannot restart the updated binary (Gatekeeper rejects it silently).
func recodesignForGatekeeper(selfPath string) {
	_ = exec.Command("xattr", "-d", "com.apple.quarantine", selfPath).Run()
	_ = exec.Command("codesign", "--force", "--sign", "-", selfPath).Run()
	_ = exec.Command("spctl", "--add", selfPath).Run()
}
