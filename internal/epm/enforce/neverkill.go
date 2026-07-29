package enforce

import (
	"path/filepath"
	"strings"
)

// neverKillPIDs are PIDs that must never be targeted regardless of platform:
// 0 (kernel/idle, meaningless as a killable PID on every OS), 1 (init/
// launchd/PID 1 on Unix), and 4 (the Windows "System" process).
var neverKillPIDs = map[int]bool{0: true, 1: true, 4: true}

// neverKillImageNames are well-known critical system process image names,
// matched case-insensitively against the trailing path element only (so
// both a bare name and a full path match) — the plan's exact list, covering
// all three platforms unconditionally, since checking a Windows name on
// Linux (etc.) is harmless and it is cheaper than branching on GOOS here.
var neverKillImageNames = map[string]bool{
	"system":       true,
	"csrss.exe":    true,
	"wininit.exe":  true,
	"winlogon.exe": true,
	"services.exe": true,
	"lsass.exe":    true,
	"smss.exe":     true,
	"systemd":      true,
	"init":         true,
	"launchd":      true,
	"kernel_task":  true,
}

// neverKillList is the safety valve: pid, imagePath, and every ancestry PID
// walked from the agent's own process are all checked. selfPID and
// selfAncestry are captured once at Enforcer construction (see
// NewEnforcer) — the agent must never kill itself or the process that
// launched it, however that ancestry chain was actually observed.
type neverKillList struct {
	selfPID      int
	selfAncestry map[int]bool
}

func newNeverKillList(selfPID int, selfAncestry []int) neverKillList {
	m := make(map[int]bool, len(selfAncestry))
	for _, pid := range selfAncestry {
		m[pid] = true
	}
	return neverKillList{selfPID: selfPID, selfAncestry: m}
}

// protects reports whether pid/imagePath must never be killed.
func (n neverKillList) protects(pid int, imagePath string) bool {
	if neverKillPIDs[pid] {
		return true
	}
	if pid == n.selfPID || n.selfAncestry[pid] {
		return true
	}
	if imagePath == "" {
		return false
	}
	name := strings.ToLower(filepath.Base(imagePath))
	return neverKillImageNames[name]
}
