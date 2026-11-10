// Package wfp is a thin binding to the Windows Filtering Platform's
// management API (fwpuclnt.dll), for the agent's own network rules (#427):
// the upload proxy blocking direct connections to the sites it inspects
// (#344), and later app control and taint blocks (#331).
//
// It binds only what the agent uses, through x/sys/windows' lazy DLL loading
// like the ETW code: no cgo, no driver, no third-party module. Everything is
// added in a dynamic session (FWPM_SESSION_FLAG_DYNAMIC), so the filters
// vanish when the session closes or the process dies: the agent fails open
// even after a crash.
//
// Windows (amd64, arm64) only; the package is empty elsewhere.
package wfp
