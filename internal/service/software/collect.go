package software

// GetSoftwareList returns the list of installed software for the current platform.
func (s *SoftwareService) GetSoftwareList() []SoftwareInfo {
	return s.filterChangedSoftware(s.platformSoftware())
}

// filterChangedSoftware implements incremental updates. Currently returns all
// software; future implementations will diff against the previous state.
func (s *SoftwareService) filterChangedSoftware(software []SoftwareInfo) []SoftwareInfo {
	return software
}
