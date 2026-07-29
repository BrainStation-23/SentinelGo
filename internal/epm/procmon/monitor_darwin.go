//go:build darwin

package procmon

import "time"

// DefaultDarwinPollInterval matches the plan's stated 250ms-1s macOS polling
// range: EndpointSecurity and libproc are both unreachable under this
// project's no-cgo constraint (EndpointSecurity additionally needs an
// Apple-granted entitlement), so gopsutil's sysctl-kern.proc.all-backed
// process listing — already a repo dependency — is the only pure-Go option.
const DefaultDarwinPollInterval = 500 * time.Millisecond

const darwinPollBufferSize = 1024

// New returns the macOS process monitor: a gopsutil-backed poll-and-diff
// (gopsutilSnapshot, in snapshot_gopsutil.go). See pollingMonitor's doc
// comment for what this backend structurally cannot see (anything
// shorter-lived than the poll interval, exit codes).
func New() Monitor {
	return newPollingMonitor(gopsutilSnapshot, DefaultDarwinPollInterval, "poll", darwinPollBufferSize)
}
