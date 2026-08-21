package health

import "testing"

func TestMicroAhToMWh(t *testing.T) {
	// 4400 mAh at 7.6V is a realistic laptop battery: 4400000 µAh at
	// 7600000 µV -> 33440 mWh.
	got := microAhToMWh(4_400_000, 7_600_000)
	want := uint64(33_440)
	if got != want {
		t.Errorf("microAhToMWh() = %d, want %d", got, want)
	}
}

func TestMAhToMWh(t *testing.T) {
	// 4400 mAh at 7600 mV -> 33440 mWh.
	got := mAhToMWh(4400, 7600)
	want := uint64(33_440)
	if got != want {
		t.Errorf("mAhToMWh() = %d, want %d", got, want)
	}
}

func TestParseIoregFields(t *testing.T) {
	const sample = `+-o AppleSmartBattery  <class AppleSmartBattery, id 0x100000328>
    {
      "CycleCount" = 234
      "IsCharging" = No
      "DesignCapacity" = 4700
      "Voltage" = 7700
      "CurrentCapacity" = 85
    }
`
	got := parseIoregFields(sample)
	if got["CycleCount"] != "234" {
		t.Errorf("CycleCount = %q, want 234", got["CycleCount"])
	}
	if got["IsCharging"] != "No" {
		t.Errorf("IsCharging = %q, want No", got["IsCharging"])
	}
	if got["DesignCapacity"] != "4700" {
		t.Errorf("DesignCapacity = %q, want 4700", got["DesignCapacity"])
	}
}

func TestParseIoregFields_Empty(t *testing.T) {
	got := parseIoregFields("no quoted keys here\njust text\n")
	if len(got) != 0 {
		t.Errorf("got %v, want empty map", got)
	}
}

func TestParseIoregInt(t *testing.T) {
	if v, ok := parseIoregInt("234"); !ok || v != 234 {
		t.Errorf("parseIoregInt(234) = (%d, %v)", v, ok)
	}
	if _, ok := parseIoregInt(""); ok {
		t.Error("parseIoregInt(empty) should return ok=false")
	}
	if _, ok := parseIoregInt("No"); ok {
		t.Error("parseIoregInt(No) should return ok=false")
	}
}
