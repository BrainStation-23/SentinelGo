package walk

import (
	"os"
	"runtime"
	"testing"
)

func TestDefaultEnv(t *testing.T) {
	env := DefaultEnv()
	if env.GOOS != runtime.GOOS || env.Getenv == nil || env.ReadDir == nil || env.FixedDrives == nil {
		t.Fatalf("env %+v", env)
	}
	if !env.Exists(os.TempDir()) || env.Exists(os.TempDir()+"/no-such-sentinelgo-dir") {
		t.Error("Exists is wrong")
	}
	if runtime.GOOS == "windows" && len(env.FixedDrives()) == 0 {
		t.Error("no fixed drive on Windows")
	}
}
