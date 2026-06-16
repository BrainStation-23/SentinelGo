package services

import (
	"testing"

	"sentinelgo/internal/models"
)

// Fixture mimics `systemctl list-units --type=service --all --no-legend`.
var systemdUnitsFixture = []byte(
	"  ssh.service      loaded active   running   OpenBSD Secure Shell server\n" +
		"  cron.service     loaded active   running   Regular background program processing daemon\n" +
		"  apache2.service  loaded inactive dead      The Apache HTTP Server\n" +
		"  snapd.service    loaded failed   failed    Snap Daemon\n",
)

// Fixture mimics `systemctl list-unit-files --type=service --no-legend`.
var systemdUnitFilesFixture = []byte(
	"ssh.service      enabled   enabled\n" +
		"cron.service     enabled   enabled\n" +
		"apache2.service  disabled  disabled\n" +
		"snapd.service    enabled   enabled\n" +
		"cups.service     masked    masked\n",
)

func TestParseSystemdUnits_count(t *testing.T) {
	units := make(map[string]models.ServiceInfo)
	parseSystemdUnits(systemdUnitsFixture, units)
	if len(units) != 4 {
		t.Fatalf("want 4 units, got %d", len(units))
	}
}

func TestParseSystemdUnits_status(t *testing.T) {
	units := make(map[string]models.ServiceInfo)
	parseSystemdUnits(systemdUnitsFixture, units)

	if units["ssh.service"].Status != "running" {
		t.Errorf("ssh.service Status = %q, want running", units["ssh.service"].Status)
	}
	if units["snapd.service"].Status != "failed" {
		t.Errorf("snapd.service Status = %q, want failed", units["snapd.service"].Status)
	}
	if units["apache2.service"].Status != "stopped" {
		t.Errorf("apache2.service Status = %q, want stopped", units["apache2.service"].Status)
	}
}

func TestParseSystemdUnits_description(t *testing.T) {
	units := make(map[string]models.ServiceInfo)
	parseSystemdUnits(systemdUnitsFixture, units)

	got := units["ssh.service"].Description
	want := "OpenBSD Secure Shell server"
	if got != want {
		t.Errorf("ssh.service Description = %q, want %q", got, want)
	}
}

func TestParseSystemdUnitFiles(t *testing.T) {
	result := parseSystemdUnitFiles(systemdUnitFilesFixture)

	if result["ssh.service"] != "automatic" {
		t.Errorf("ssh.service = %q, want automatic", result["ssh.service"])
	}
	if result["apache2.service"] != "disabled" {
		t.Errorf("apache2.service = %q, want disabled", result["apache2.service"])
	}
	if result["cups.service"] != "masked" {
		t.Errorf("cups.service = %q, want masked", result["cups.service"])
	}
}

func TestNormalizeSystemdState(t *testing.T) {
	cases := []struct{ in, want string }{
		{"enabled", "automatic"},
		{"enabled-runtime", "automatic"},
		{"disabled", "disabled"},
		{"static", "static"},
		{"masked", "masked"},
		{"masked-runtime", "masked"},
		{"indirect", "indirect"},
		{"", "unknown"},
		{"generated", "generated"},
	}
	for _, c := range cases {
		if got := normalizeSystemdState(c.in); got != c.want {
			t.Errorf("normalizeSystemdState(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSystemdStatus(t *testing.T) {
	cases := []struct{ active, sub, want string }{
		{"active", "running", "running"},
		{"active", "exited", "active"},
		{"inactive", "dead", "stopped"},
		{"failed", "failed", "failed"},
		{"activating", "start", "activating"},
	}
	for _, c := range cases {
		if got := systemdStatus(c.active, c.sub); got != c.want {
			t.Errorf("systemdStatus(%q,%q) = %q, want %q", c.active, c.sub, got, c.want)
		}
	}
}

func TestStripANSI(t *testing.T) {
	input := "\x1b[1m\x1b[32mssh.service\x1b[0m  loaded active running"
	got := stripANSI(input)
	want := "ssh.service  loaded active running"
	if got != want {
		t.Errorf("stripANSI = %q, want %q", got, want)
	}
}
