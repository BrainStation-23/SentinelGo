package session

import "testing"

func TestAcquireHelperLock_SingleInstance(t *testing.T) {
	release, ok, err := AcquireHelperLock()
	if err != nil || !ok {
		t.Fatalf("first lock: ok=%v err=%v", ok, err)
	}
	if _, ok2, err := AcquireHelperLock(); err != nil || ok2 {
		t.Errorf("second lock in the same session: ok=%v err=%v, want held", ok2, err)
	}
	release()
	release2, ok, err := AcquireHelperLock()
	if err != nil || !ok {
		t.Fatalf("lock after release: ok=%v err=%v", ok, err)
	}
	release2()
}
