package services

import "testing"

func TestNormalizeServicesStatus(t *testing.T) {
	cases := []struct{ in, want string }{
		{"running", "running"},
		{"stopped", "stopped"},
		{"paused", "paused"},
		{"starting", "start_pending"},
		{"activating", "start_pending"},
		{"stopping", "stop_pending"},
		{"deactivating", "stop_pending"},
		{"active", "running"},
		{"inactive", "stopped"},
		{"failed", "failed"},
		{"", "unknown"},
		{"someother", "unknown"},
	}
	for _, c := range cases {
		if got := normalizeServicesStatus(c.in); got != c.want {
			t.Errorf("normalizeServicesStatus(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeServicesStartMode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"automatic", "auto"},
		{"auto_delayed", "auto_delayed"},
		{"manual", "manual"},
		{"disabled", "disabled"},
		{"masked", "disabled"},
		{"masked-runtime", "disabled"},
		{"boot", "boot"},
		{"system", "system"},
		{"static", "static"},
		{"indirect", "static"},
		{"generated", ""},
		{"unknown", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeServicesStartMode(c.in); got != c.want {
			t.Errorf("normalizeServicesStartMode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeServicesSource(t *testing.T) {
	cases := []struct{ in, want string }{
		{"windows_services", "windows_service"},
		{"systemd", "systemd"},
		{"launchd", "launchd"},
		{"openrc", "openrc"},
		{"other", "other"},
		{"", ""},
	}
	for _, c := range cases {
		if got := normalizeServicesSource(c.in); got != c.want {
			t.Errorf("normalizeServicesSource(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
