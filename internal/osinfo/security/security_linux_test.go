package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKnownAVServices(t *testing.T) {
	seen := map[string]bool{}
	for _, svc := range knownAVServices {
		if svc.service == "" {
			t.Errorf("empty service name for %q", svc.name)
		}
		if svc.name == "" {
			t.Errorf("empty display name for service %q", svc.service)
		}
		seen[svc.service] = true
	}
	// Ensure expected services are present.
	required := []string{"clamav-daemon", "falcon-sensor", "cbsensor"}
	for _, r := range required {
		if !seen[r] {
			t.Errorf("expected service %q not found in knownAVServices", r)
		}
	}
}

func writeModprobeConf(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestUsbStorageStateFromModprobeDir(t *testing.T) {
	cases := []struct {
		name     string
		file     string
		content  string
		want     string
	}{
		{"blacklist directive disables", "usb.conf", "blacklist usb_storage\n", "disabled"},
		{"install /bin/false disables", "usb.conf", "install usb_storage /bin/false\n", "disabled"},
		{"unrelated blacklist ignored", "other.conf", "blacklist some_other_module\n", ""},
		{"non-conf file ignored", "usb.txt", "blacklist usb_storage\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeModprobeConf(t, dir, c.file, c.content)
			if got := usbStorageStateFromModprobeDir(dir); got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}

	t.Run("empty dir returns empty", func(t *testing.T) {
		if got := usbStorageStateFromModprobeDir(t.TempDir()); got != "" {
			t.Errorf("got %q, want empty string", got)
		}
	})
	t.Run("nonexistent dir returns empty", func(t *testing.T) {
		if got := usbStorageStateFromModprobeDir("/nonexistent/modprobe.d"); got != "" {
			t.Errorf("got %q, want empty string", got)
		}
	})
}

func TestParseSEStatusOutput(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		want   string
	}{
		{"enforcing mode", "SELinux status:                 enabled\nCurrent mode:                   enforcing\n", "enforcing"},
		{"permissive mode", "SELinux status:                 enabled\nCurrent mode:                   permissive\n", "permissive"},
		{"disabled status line", "SELinux status:                 disabled\n", "disabled"},
		{"empty output", "", ""},
		{"unrecognised mode", "Current mode:   confused\n", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := parseSEStatusOutput(c.input)
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestKernelLockdownParsing(t *testing.T) {
	cases := []struct {
		content string
		want    string
	}{
		{"none [integrity] confidentiality", "integrity"},
		{"[none] integrity confidentiality", "none"},
		{"none integrity [confidentiality]", "confidentiality"},
		{"none integrity confidentiality", "unknown"},
	}
	for _, c := range cases {
		got := "unknown"
		for _, mode := range []string{"confidentiality", "integrity", "none"} {
			if strings.Contains(c.content, "["+mode+"]") {
				got = mode
				break
			}
		}
		if got != c.want {
			t.Errorf("content=%q: got %q, want %q", c.content, got, c.want)
		}
	}
}
