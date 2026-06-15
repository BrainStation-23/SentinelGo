package software

import "time"

// collectCmdTimeout bounds every external enumeration command (package managers,
// system_profiler, PowerShell queries, etc.). A tool that hangs (e.g. a held dpkg
// lock or a stalled system_profiler) must report failure rather than block the
// software-sync goroutine indefinitely — a never-returning collector would wedge
// every later sync tick (the scheduler skips a task while a prior run is still
// running) until the process restarts. On timeout the command errors, the source
// returns ok=false, and the store leaves that source's rows untouched.
const collectCmdTimeout = 30 * time.Second

// GetSoftwareList returns the list of installed software for the current platform
// along with the set of source categories that were authoritatively scanned. The
// caller passes scannedSources to the store so that only successfully-scanned
// sources are reconciled for uninstalls — a failed scan never demotes its rows.
func (s *SoftwareService) GetSoftwareList() ([]SoftwareInfo, map[string]bool) {
	list, scanned := s.platformSoftware()
	return s.filterChangedSoftware(list), scanned
}

// filterChangedSoftware implements incremental updates. Currently returns all
// software; future implementations will diff against the previous state.
func (s *SoftwareService) filterChangedSoftware(software []SoftwareInfo) []SoftwareInfo {
	return software
}
