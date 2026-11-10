package walk

import (
	"os"
	"os/exec"
	"testing"
)

// LowerSelf changes the whole process, so it runs in a child copy of the
// test binary.
func TestLowerSelf(t *testing.T) {
	if os.Getenv("SENTINELGO_LOWERSELF_CHILD") == "1" {
		if err := LowerSelf(); err != nil {
			t.Fatalf("LowerSelf: %v", err)
		}
		if err := checkLowered(); err != nil {
			t.Fatal(err)
		}
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestLowerSelf$", "-test.v") // #nosec G204 -- the test binary itself
	cmd.Env = append(os.Environ(), "SENTINELGO_LOWERSELF_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}
