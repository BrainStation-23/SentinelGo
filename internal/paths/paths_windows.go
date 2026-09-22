//go:build windows

package paths

import (
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/windows"
)

// dirName is the folder created under both %ProgramFiles% and %ProgramData%.
const dirName = "SentinelGo"

// legacyWindowsInstallDir is where the agent installed before the relocation.
// A directory created directly under C:\ inherits the drive root's inherit-only
// "Authenticated Users:(OI)(CI)(IO)(M)" ACE, which is what made the binary
// replaceable by any standard user. Retained only so migration can find, secure
// and eventually retire the old tree.
const legacyWindowsInstallDir = `C:\SentinelGo`

// Known-folder lookups go through the shell, so resolve each once.
var (
	programFilesOnce sync.Once
	programFilesRoot string

	programDataOnce sync.Once
	programDataRoot string
)

func installDir() string {
	programFilesOnce.Do(func() {
		programFilesRoot = knownFolder(
			windows.FOLDERID_ProgramFiles,
			"ProgramFiles",
			`C:\Program Files`,
		)
	})
	return filepath.Join(programFilesRoot, dirName)
}

func dataDir() string {
	programDataOnce.Do(func() {
		programDataRoot = knownFolder(
			windows.FOLDERID_ProgramData,
			"ProgramData",
			`C:\ProgramData`,
		)
	})
	return filepath.Join(programDataRoot, dirName)
}

func legacyInstallDir() string { return legacyWindowsInstallDir }

// knownFolder resolves a Windows known folder, falling back to an environment
// variable and then to a fixed default.
//
// The known-folder API is preferred over the environment because the
// environment is inherited and therefore attacker-influenceable in a way the
// shell API is not, and because it stays correct on systems where Windows was
// installed to a non-default drive. The fallbacks exist so a failure to resolve
// degrades to the conventional location rather than to an empty path, which
// would silently place agent state at a relative path.
func knownFolder(id *windows.KNOWNFOLDERID, envVar, fallback string) string {
	if path, err := windows.KnownFolderPath(id, windows.KF_FLAG_DEFAULT); err == nil && path != "" {
		return path
	}
	if path := os.Getenv(envVar); path != "" {
		return path
	}
	return fallback
}
