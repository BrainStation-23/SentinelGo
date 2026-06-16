package software

import "time"

// collectCmdTimeout bounds every external enumeration command (package managers,
// system_profiler, PowerShell queries, etc.). A tool that hangs must report
// failure rather than block the software-sync goroutine indefinitely.
const collectCmdTimeout = 30 * time.Second

// GetSoftwareList returns the list of currently installed software for the
// current platform.
func (s *SoftwareService) GetSoftwareList() []SoftwareInfo {
	list, _ := s.platformSoftware()
	return list
}

// GetSoftwareListWithStatus returns the installed-software list and whether the
// scan was complete. complete is false when a bulk collector (e.g. the Windows
// registry query) failed, signalling that the result must not be used to prune
// the stored catalog. Callers that only need the list use GetSoftwareList.
func (s *SoftwareService) GetSoftwareListWithStatus() ([]SoftwareInfo, bool) {
	return s.platformSoftware()
}
