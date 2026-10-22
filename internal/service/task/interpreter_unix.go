//go:build !windows

package task

import (
	"errors"
	"path/filepath"

	"sentinelgo/internal/binpath"
)

// errPwshMissing fails a .ps1 task on a device without PowerShell 7, instead
// of the exec-format error running the script directly would give. The agent
// only advertises script_pwsh_v1 when pwsh is found, so the backend should
// not send such a task, but a stale inventory can still let one through.
var errPwshMissing = errors.New("PowerShell (pwsh) is not installed on this device")

// lookupBinary resolves an interpreter strictly (no PATH fallback). A var so
// tests can choose which interpreters exist.
var lookupBinary = binpath.Lookup

// scriptArgv returns the command line that runs scriptPath on macOS and
// Linux: the interpreter its extension picks, then the script and the payload
// path. Scripts with an interpreter are run through it rather than through
// their shebang, because the console puts its own lines above line 1.
func scriptArgv(scriptPath, payloadPath string) ([]string, error) {
	switch filepath.Ext(scriptPath) {
	case ".sh", ".bash":
		return []string{binpath.Resolve("bash"), scriptPath, payloadPath}, nil
	case ".zsh":
		return []string{binpath.Resolve("zsh"), scriptPath, payloadPath}, nil
	case ".py":
		return []string{binpath.Resolve("python3"), scriptPath, payloadPath}, nil
	case ".ps1":
		// Same arguments as on Windows, so one script runs the same everywhere.
		// Unlike bash, pwsh is resolved strictly: it's the same check that
		// decides whether script_pwsh_v1 is advertised.
		pwsh, ok := lookupBinary("pwsh")
		if !ok {
			return nil, errPwshMissing
		}
		return []string{pwsh, "-NoProfile", "-NonInteractive", "-File", scriptPath, "-PayloadPath", payloadPath}, nil
	default:
		return []string{scriptPath, payloadPath}, nil
	}
}
