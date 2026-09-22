//go:build !windows

package migrate

// Run is a no-op on non-Windows platforms.
//
// The relocation exists because C:\SentinelGo inherited the drive root's
// "Authenticated Users:(OI)(CI)(IO)(M)" ACE. /opt/sentinelgo has no equivalent
// problem: it is root-owned and mode 0755, so an unprivileged user cannot
// replace the binary. The exposure on Unix was the installer applying
// "chmod -R 755" across the config directory and chowning the root-executed
// binary to an unprivileged account -- both fixed in install.sh, neither needing
// a new location.
func Run() Result {
	return Result{Reason: "no relocation needed on this platform"}
}
