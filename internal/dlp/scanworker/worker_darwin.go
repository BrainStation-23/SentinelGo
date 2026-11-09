package scanworker

import (
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"syscall"

	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

// workerFD is the descriptor the worker's socket arrives on.
const workerFD = 3

// Worker limits.
const (
	workerMemoryLimit = 1 << 30
	workerOpenFiles   = 64
	sandboxNamed      = 0x0001 // SANDBOX_NAMED
)

// Serve is `sentinelgo dlp-scan`: it sandboxes the process, then serves scan
// requests on fd 3 until the service closes the socket. It never opens a path.
func Serve() error {
	desc, err := sandbox()
	if err != nil {
		return fmt.Errorf("sandbox: %w", err)
	}
	c, _, err := fileConn(os.NewFile(workerFD, "scan-socket"))
	if err != nil {
		return fmt.Errorf("fd %d: %w", workerFD, err)
	}
	return serve(c, desc)
}

// sandbox applies the limits and the profile for the level the pool asked
// for. A failed limit or profile is fatal: the pool then tries a lower level.
func sandbox() (string, error) {
	debug.SetMemoryLimit(workerMemoryLimit)
	for _, l := range []struct {
		res int
		max uint64
	}{{unix.RLIMIT_CORE, 0}, {unix.RLIMIT_NOFILE, workerOpenFiles}} {
		if err := unix.Setrlimit(l.res, &unix.Rlimit{Cur: l.max, Max: l.max}); err != nil {
			return "", fmt.Errorf("rlimit %d: %w", l.res, err)
		}
	}
	level, _ := strconv.Atoi(os.Getenv(sandboxLevelEnv))
	profile := map[int]string{levelPureComputation: "pure-computation", levelNoNetwork: "no-network"}[level]
	if profile == "" {
		return "rlimits", nil
	}
	if err := sandboxInit(profile); err != nil {
		return "", err
	}
	if level == levelPureComputation {
		// Check it took: opening a path must now fail.
		if f, err := os.Open("/etc/hosts"); err == nil {
			_ = f.Close()
			return "", fmt.Errorf("the %s profile doesn't deny file access", profile)
		}
	}
	return "rlimits,sandbox=" + profile, nil
}

// sandboxInit applies a named sandbox profile (libsystem_sandbox, through
// purego). It applies to the whole process and can't be undone.
func sandboxInit(profile string) error {
	lib, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_GLOBAL|purego.RTLD_NOW)
	if err != nil {
		return fmt.Errorf("load libSystem: %w", err)
	}
	var initFn func(profile string, flags uint64, errbuf *uintptr) int32
	purego.RegisterLibFunc(&initFn, lib, "sandbox_init")
	var errbuf uintptr
	if rc := initFn(profile, sandboxNamed, &errbuf); rc != 0 {
		return fmt.Errorf("sandbox_init %s: %w", profile, syscall.EPERM)
	}
	return nil
}
