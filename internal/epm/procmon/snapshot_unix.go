//go:build linux || darwin

package procmon

import "github.com/shirou/gopsutil/v4/process"

// gopsutilSnapshot lists every running process and resolves its parent PID,
// executable path, and command line. Each of those is its own syscall in
// gopsutil, so this is O(processes) syscalls per call — acceptable at the
// 250ms-1s polling cadence pollingMonitor runs it at, not something to call
// more often. A process that exits mid-enumeration simply keeps its
// zero-value ParentPID/ImagePath/CommandLine; it is still included in the
// snapshot by PID so it is not misread as having already exited on this
// tick.
//
// One file for linux and darwin (matching internal/epm/transport_unix.go's
// precedent) rather than untagged: gopsutil's process package IS itself
// pure-Go and cross-platform, but this function specifically is only ever
// called by monitor_darwin.go (the primary macOS backend) and
// monitor_linux.go (the fallback used when the netlink proc connector
// cannot be opened, e.g. missing CAP_NET_ADMIN) — Windows uses EvtSubscribe
// exclusively and never calls this, so leaving it untagged made it dead
// code on a windows-only build, which is what golangci-lint's per-GOOS lint
// pass correctly flagged.
func gopsutilSnapshot() (map[int]procInfo, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}

	snap := make(map[int]procInfo, len(procs))
	for _, p := range procs {
		info := procInfo{}
		if ppid, err := p.Ppid(); err == nil {
			info.ParentPID = int(ppid)
		}
		if exe, err := p.Exe(); err == nil {
			info.ImagePath = exe
		}
		if cmdline, err := p.Cmdline(); err == nil {
			info.CommandLine = cmdline
		}
		snap[int(p.Pid)] = info
	}
	return snap, nil
}
