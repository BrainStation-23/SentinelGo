package collector

// Source names of the Windows event channels whose events the parser grades
// by event ID (#484). They are what generateSource returns for each channel;
// TestSourceConstants checks that on Windows. They live in an untagged file so
// the parser can use them on every OS.
const (
	SourceWindowsSecurity      = "windows_security"
	SourceWindowsSystem        = "windows_system"
	SourceWindowsDefender      = "windows_microsoft_windows_windows_defender_operational"
	SourceWindowsPowerShell    = "windows_microsoft_windows_powershell_operational"
	SourceWindowsTaskScheduler = "windows_microsoft_windows_taskscheduler_operational"
	SourceWindowsFirewall      = "windows_microsoft_windows_windows_firewall_with_advanced_security_firewall"
	SourceWindowsRemoteDesktop = "windows_microsoft_windows_terminalservices_remoteconnectionmanager_operational"
)
