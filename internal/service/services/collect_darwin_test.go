package services

import (
	"testing"

	"sentinelgo/internal/models"
)

// Fixture mimics `launchctl list` output (tab-separated, first line is header).
var launchctlFixture = []byte(
	"PID\tStatus\tLabel\n" +
		"-\t0\tcom.apple.ATS\n" +
		"1234\t-\tcom.apple.loginwindow\n" +
		"-\t1\tcom.docker.vmnetd\n" +
		"-\t0\tcom.example.myapp\n",
)

func TestParseLaunchctlList_count(t *testing.T) {
	svcs := parseLaunchctlList(launchctlFixture)
	if len(svcs) != 4 {
		t.Fatalf("want 4 services, got %d", len(svcs))
	}
}

func TestParseLaunchctlList_fields(t *testing.T) {
	svcs := parseLaunchctlList(launchctlFixture)

	byName := make(map[string]models.ServiceInfo)
	for _, s := range svcs {
		byName[s.Name] = s
	}

	ats := byName["com.apple.ATS"]
	if ats.Status != "stopped" {
		t.Errorf("com.apple.ATS Status = %q, want stopped", ats.Status)
	}
	if ats.StartType != "system" {
		t.Errorf("com.apple.ATS StartType = %q, want system", ats.StartType)
	}

	loginwindow := byName["com.apple.loginwindow"]
	if loginwindow.Status != "running" {
		t.Errorf("com.apple.loginwindow Status = %q, want running", loginwindow.Status)
	}
	if loginwindow.PID != 1234 {
		t.Errorf("com.apple.loginwindow PID = %d, want 1234", loginwindow.PID)
	}

	docker := byName["com.docker.vmnetd"]
	if docker.Status != "failed" {
		t.Errorf("com.docker.vmnetd Status = %q, want failed", docker.Status)
	}

	myapp := byName["com.example.myapp"]
	if myapp.StartType != "unknown" {
		t.Errorf("com.example.myapp StartType = %q, want unknown", myapp.StartType)
	}
}

func TestDarwinStatus(t *testing.T) {
	cases := []struct{ pid, status, want string }{
		{"1234", "-", "running"},
		{"-", "0", "stopped"},
		{"-", "-", "stopped"},
		{"-", "1", "failed"},
		{"-", "255", "failed"},
	}
	for _, c := range cases {
		if got := darwinStatus(c.pid, c.status); got != c.want {
			t.Errorf("darwinStatus(%q,%q) = %q, want %q", c.pid, c.status, got, c.want)
		}
	}
}

func TestInferDarwinStartType(t *testing.T) {
	if got := inferDarwinStartType("com.apple.ATS"); got != "system" {
		t.Errorf("com.apple.ATS = %q, want system", got)
	}
	if got := inferDarwinStartType("com.docker.vmnetd"); got != "unknown" {
		t.Errorf("com.docker.vmnetd = %q, want unknown", got)
	}
}
