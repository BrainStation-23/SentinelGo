package dlp

import (
	"runtime"
	"testing"

	"sentinelgo/internal/dlp/policy"
)

func TestHelperFileChannels(t *testing.T) {
	for raw, want := range map[string]bool{
		`{"schema_version":1,"version":"v","enabled":true,"modules":{"files":{"enabled":true,"channels":{"file.network_share":true}}}}`: runtime.GOOS == "windows",
		`{"schema_version":1,"version":"v","enabled":true,"modules":{"files":{"enabled":true,"channels":{"file.cloud_sync":true}}}}`:    runtime.GOOS == "windows",
		`{"schema_version":1,"version":"v","enabled":true,"modules":{"files":{"enabled":true,"channels":{"file.removable":true}}}}`:     false,
		`{"schema_version":1,"version":"v","enabled":true,"modules":{"files":{"enabled":false,"channels":{"file.cloud_sync":true}}}}`:   false,
	} {
		b, err := policy.Decode([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if got := helperFileChannels(b); got != want {
			t.Errorf("%s: %v, want %v", raw, got, want)
		}
	}
}
