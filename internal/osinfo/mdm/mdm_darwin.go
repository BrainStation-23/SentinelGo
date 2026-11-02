package mdm

import (
	"errors"
	"io/fs"
	"os"
	"sync"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

// Test seams.
var (
	runCommand       = shared.RunCommand
	runCommandOutput = shared.RunCommandOutput
	now              = time.Now
	openFile         = func(name string) (*os.File, error) { return os.Open(name) } // #nosec G304 -- fixed system path
)

// tccDB is the system TCC database. Opening it needs Full Disk Access, even
// as root, so it shows whether the agent has been granted it.
const tccDB = "/Library/Application Support/com.apple.TCC/TCC.db"

// adeRefresh is how long a `profiles show -type enrollment` result is reused.
// The command asks Apple's servers, so it isn't run on every inventory.
const adeRefresh = 24 * time.Hour

var adeCache struct {
	mu  sync.Mutex
	at  time.Time
	cfg adeConfig
}

func collect(ourHost string) *shared.MDMInfo {
	statusOut, _ := runCommand("profiles", "status", "-type", "enrollment")
	st := parseEnrollmentStatus(statusOut)

	var ade adeConfig
	if !st.enrolled || !st.viaDEP { // an ADE-enrolled Mac is assigned by definition
		ade = cachedADEConfig()
	}

	bootstrapOut, _ := runCommand("profiles", "status", "-type", "bootstraptoken")
	hwOut, _ := runCommand("system_profiler", "SPHardwareDataType", "-json")
	info := buildMacInfo(st, ade, parseBootstrapToken(bootstrapOut), parseHardwareIdentity(hwOut), ourHost, now())

	// Computer-level configuration profiles: which settings MDM enforces.
	if xml, err := runCommand("profiles", "-C", "-o", "stdout-xml"); err == nil {
		info.ProfilePayloadTypes = parsePayloadTypes(xml)
		info.ManagedSettings = managedSettings(info.ProfilePayloadTypes)
	}
	info.Grants.FullDiskAccess = fullDiskAccess()
	return info
}

// fullDiskAccess reports whether the agent can open the TCC database: true
// with Full Disk Access, false without it, nil when it can't tell.
func fullDiskAccess() *bool {
	f, err := openFile(tccDB)
	switch {
	case err == nil:
		_ = f.Close()
		return boolPtr(true)
	case errors.Is(err, fs.ErrPermission):
		return boolPtr(false)
	default:
		return nil
	}
}

// cachedADEConfig returns the ADE assignment, asking Apple at most once per
// adeRefresh. A result that couldn't be determined isn't cached, so the next
// inventory tries again.
func cachedADEConfig() adeConfig {
	adeCache.mu.Lock()
	defer adeCache.mu.Unlock()
	if !adeCache.at.IsZero() && now().Sub(adeCache.at) < adeRefresh {
		return adeCache.cfg
	}
	// Non-zero exit for "not DEP enabled", so read combined output.
	out, _, err := runCommandOutput("profiles", "show", "-type", "enrollment")
	if err != nil {
		return adeConfig{}
	}
	cfg := parseADEConfig(out)
	if cfg.assigned != nil {
		adeCache.at, adeCache.cfg = now(), cfg
	}
	return cfg
}
