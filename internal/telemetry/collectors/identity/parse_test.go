package identity

import "testing"

func TestParsePlatformUUID(t *testing.T) {
	const sample = `+-o IOPlatformExpertDevice
    | {
    |   "IOPlatformUUID" = "12345678-ABCD-1234-ABCD-1234567890AB"
    |   "IOPlatformSerialNumber" = "C02ABCDEFGH"
    | }`

	got := parsePlatformUUID(sample)
	want := "12345678-ABCD-1234-ABCD-1234567890AB"
	if got != want {
		t.Errorf("parsePlatformUUID() = %q, want %q", got, want)
	}
}

func TestParsePlatformUUID_Missing(t *testing.T) {
	if got := parsePlatformUUID("no matching key here"); got != "" {
		t.Errorf("parsePlatformUUID() = %q, want empty", got)
	}
}

func TestParsePlatformUUID_Empty(t *testing.T) {
	if got := parsePlatformUUID(""); got != "" {
		t.Errorf("parsePlatformUUID(\"\") = %q, want empty", got)
	}
}
