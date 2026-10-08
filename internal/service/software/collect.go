package software

import (
	"path/filepath"
	"time"
)

// collectCmdTimeout bounds every external enumeration command (package managers,
// system_profiler, PowerShell queries, etc.). A tool that hangs must report
// failure rather than block the software-sync goroutine indefinitely.
const collectCmdTimeout = 30 * time.Second

// platformSoftwareFn is the per-OS collector behind GetSoftwareList and
// GetSoftwareListWithStatus. It is a var so tests can stub the real scan, which
// shells out to package managers / system_profiler / PowerShell and can be slow.
var platformSoftwareFn = (*SoftwareService).platformSoftware

// GetSoftwareList returns the list of currently installed software for the
// current platform.
func (s *SoftwareService) GetSoftwareList() []SoftwareInfo {
	list, _ := platformSoftwareFn(s)
	return list
}

// GetSoftwareListWithStatus returns the installed-software list and whether the
// scan was complete. complete is false when a bulk collector (e.g. the Windows
// registry query) failed, signalling that the result must not be used to prune
// the stored catalog. Callers that only need the list use GetSoftwareList.
func (s *SoftwareService) GetSoftwareListWithStatus() ([]SoftwareInfo, bool) {
	return platformSoftwareFn(s)
}

// browserExtDirs joins home with each OS-specific relative sub-path to build
// absolute glob patterns for a browser's extension/profile directories.
func browserExtDirs(home string, relPaths ...string) []string {
	globs := make([]string, len(relPaths))
	for i, rel := range relPaths {
		globs[i] = filepath.Join(home, rel)
	}
	return globs
}
