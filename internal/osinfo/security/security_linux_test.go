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
		name    string
		file    string
		content string
		want    string
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
		name  string
		input string
		want  string
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

func TestSecureBootFromEFIVars(t *testing.T) {
	t.Run("dir not found returns unknown", func(t *testing.T) {
		got := secureBootFromEFIVars(filepath.Join(t.TempDir(), "nonexistent"))
		if got != "unknown" {
			t.Errorf("got %q, want unknown", got)
		}
	})

	t.Run("no SecureBoot file returns unknown", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "OtherVar-12345"), []byte{0, 0, 0, 0, 1}, 0600); err != nil {
			t.Fatal(err)
		}
		got := secureBootFromEFIVars(dir)
		if got != "unknown" {
			t.Errorf("got %q, want unknown", got)
		}
	})

	t.Run("SecureBoot enabled (byte 4 == 1)", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"), []byte{0x07, 0x00, 0x00, 0x00, 0x01}, 0600); err != nil {
			t.Fatal(err)
		}
		got := secureBootFromEFIVars(dir)
		if got != "enabled" {
			t.Errorf("got %q, want enabled", got)
		}
	})

	t.Run("SecureBoot disabled (byte 4 == 0)", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"), []byte{0x07, 0x00, 0x00, 0x00, 0x00}, 0600); err != nil {
			t.Fatal(err)
		}
		got := secureBootFromEFIVars(dir)
		if got != "disabled" {
			t.Errorf("got %q, want disabled", got)
		}
	})

	t.Run("SecureBoot file too short returns unknown", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"), []byte{0x01, 0x00}, 0600); err != nil {
			t.Fatal(err)
		}
		got := secureBootFromEFIVars(dir)
		if got != "unknown" {
			t.Errorf("got %q, want unknown", got)
		}
	})
}

func TestUsbStorageStateFromConfFile(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"blacklist directive disables", "blacklist usb_storage\n", "disabled"},
		{"install to /bin/false disables", "install usb_storage /bin/false\n", "disabled"},
		{"comment is ignored", "# blacklist usb_storage\n", ""},
		{"unrelated content returns empty", "blacklist nouveau\noptions drm_kms_helper poll=0\n", ""},
		{"mixed case blacklist matches", "BLACKLIST usb_storage\n", "disabled"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := os.CreateTemp(t.TempDir(), "modprobe-*.conf")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString(c.content); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			got := usbStorageStateFromConfFile(f.Name())
			if got != c.want {
				t.Errorf("got %q, want %q", got, c.want)
			}
		})
	}
	t.Run("nonexistent file returns empty", func(t *testing.T) {
		got := usbStorageStateFromConfFile(filepath.Join(t.TempDir(), "missing.conf"))
		if got != "" {
			t.Errorf("got %q, want empty string", got)
		}
	})
}

func TestParseSSHConfigData(t *testing.T) {
	cases := []struct {
		name         string
		input        string
		wantRoot     string
		wantPassword string
		wantPubkey   string
	}{
		{
			name:         "all enabled",
			input:        "PermitRootLogin yes\nPasswordAuthentication yes\nPubkeyAuthentication yes\n",
			wantRoot:     "Enabled",
			wantPassword: "Enabled",
			wantPubkey:   "Enabled",
		},
		{
			name:         "all disabled",
			input:        "PermitRootLogin no\nPasswordAuthentication no\nPubkeyAuthentication no\n",
			wantRoot:     "Disabled",
			wantPassword: "Disabled",
			wantPubkey:   "Disabled",
		},
		{
			name:         "prohibit-password is Disabled root login",
			input:        "PermitRootLogin prohibit-password\n",
			wantRoot:     "Disabled",
			wantPassword: "Unknown",
			wantPubkey:   "Unknown",
		},
		{
			name:         "commented lines ignored",
			input:        "# PermitRootLogin yes\nPermitRootLogin no\n",
			wantRoot:     "Disabled",
			wantPassword: "Unknown",
			wantPubkey:   "Unknown",
		},
		{
			name:         "empty config yields Unknown",
			input:        "",
			wantRoot:     "Unknown",
			wantPassword: "Unknown",
			wantPubkey:   "Unknown",
		},
		{
			name:         "case-insensitive keys",
			input:        "permitrootlogin yes\npasswordauthentication no\npubkeyauthentication yes\n",
			wantRoot:     "Enabled",
			wantPassword: "Disabled",
			wantPubkey:   "Enabled",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root, pw, pk := parseSSHConfigData(c.input)
			if root != c.wantRoot {
				t.Errorf("rootLogin: got %q, want %q", root, c.wantRoot)
			}
			if pw != c.wantPassword {
				t.Errorf("passwordAuth: got %q, want %q", pw, c.wantPassword)
			}
			if pk != c.wantPubkey {
				t.Errorf("pubkeyAuth: got %q, want %q", pk, c.wantPubkey)
			}
		})
	}
}

func TestCountAptSecurityUpdates(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  int
	}{
		{
			name: "only -security pocket lines counted",
			input: "Inst linux-image-6.8.0 [6.8.0-57] (6.8.0-58 Ubuntu:24.04/noble-security [amd64])\n" +
				"Inst openssh-server [1:9.6p1-3] (1:9.6p1-3ubuntu0.1 Ubuntu:24.04/noble-security [amd64])\n" +
				"Inst firefox [125.0] (126.0 Ubuntu:24.04/noble-updates [amd64])\n",
			want: 2,
		},
		{
			name:  "package with 'security' in name but not -security pocket not counted",
			input: "Inst libsecurity-apparmor-perl [3.0] (3.1 Ubuntu:24.04/noble [amd64])\n",
			want:  0,
		},
		{
			name:  "no updates",
			input: "All packages are up to date.\n",
			want:  0,
		},
		{
			name:  "empty output",
			input: "",
			want:  0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := countAptSecurityUpdates(c.input)
			if got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}

func TestCountYumSecurityUpdates(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  int
	}{
		{
			name: "counts security update package lines",
			input: "Loaded plugins: fastestmirror\n" +
				"Last metadata expiration check: 0:12:34 ago\n" +
				"kernel.x86_64         4.18.0-477.15.1.el8_8   baseos-security\n" +
				"openssl.x86_64        1:1.1.1k-12.el8_9        baseos-security\n" +
				"curl.x86_64           7.61.1-30.el8_9.3        baseos\n",
			want: 2,
		},
		{
			name:  "no security updates",
			input: "Loaded plugins: fastestmirror\nNo packages needed for security; 0 packages available\n",
			want:  0,
		},
		{
			name:  "empty output",
			input: "",
			want:  0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := countYumSecurityUpdates(c.input)
			if got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
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
