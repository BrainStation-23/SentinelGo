package ram

import (
	"testing"
)

func TestGetRAMs_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in -short mode")
	}

	info := Get()
	if info.TotalCapacity == 0 {
		t.Fatal("Get() returned zero TotalCapacity")
	}
	t.Logf("TotalCapacity: %d bytes", info.TotalCapacity)
	for i, stick := range info.RAMs {
		if stick.Capacity == 0 {
			t.Errorf("RAM stick %d has zero Capacity", i)
		}
		t.Logf("stick[%d]: %+v", i, stick)
	}
}
