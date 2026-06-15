package software

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
