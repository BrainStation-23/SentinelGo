package mdm

import (
	"sync"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

// Test seams.
var (
	runCommand       = shared.RunCommand
	runCommandOutput = shared.RunCommandOutput
	now              = time.Now
)

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
	return buildMacInfo(st, ade, parseBootstrapToken(bootstrapOut), parseHardwareIdentity(hwOut), ourHost, now())
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
