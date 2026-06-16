package software

import "time"

// collectCmdTimeout bounds every external enumeration command (package managers,
// system_profiler, PowerShell queries, etc.). A tool that hangs must report
// failure rather than block the software-sync goroutine indefinitely.
const collectCmdTimeout = 30 * time.Second

// GetSoftwareList returns the list of currently installed software for the
// current platform.
func (s *SoftwareService) GetSoftwareList() []SoftwareInfo {
	return s.platformSoftware()
}
