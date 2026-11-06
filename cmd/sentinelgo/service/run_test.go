package service

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"sentinelgo/internal/enrollment"
	"sentinelgo/internal/lockfile"
	"sentinelgo/internal/osinfo/shared"
)

// The daemon entry point (-run and launchd service mode both use
// runUntilSignal, #399) on a generic macOS package: no supabase_url, and the
// managed-preferences token arrives after the daemon started. It keeps
// waiting, enrolls once the token is there, then starts the integration.
func TestRunUntilSignal_EnrollsWhenTokenArrivesLater(t *testing.T) {
	_, cfg := useTempLock(t)
	tokenMayArriveLater = true
	countingEnroll(3, enrollment.ErrNoToken) // the profile lands on the 4th try
	exited := make(chan int, 1)
	exitProcess = func(code int) { exited <- code }

	sig := make(chan os.Signal, 1)
	done := make(chan error, 1)
	p := NewProgram(cfg)
	go func() { done <- runUntilSignal(p, sig) }()

	select {
	case code := <-exited:
		// The integration started after enrolling: the stub enrolls without
		// filling the config, so its validation is what fails here.
		if code != int(ExitConfigInvalid) {
			t.Errorf("exit code %d, want %d", code, ExitConfigInvalid)
		}
	case err := <-done:
		t.Fatalf("runUntilSignal returned %v before enrolling", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the integration never started after the token arrived")
	}

	sig <- syscall.SIGTERM
	if err := <-done; err != nil {
		t.Errorf("runUntilSignal() = %v after SIGTERM, want nil", err)
	}
}

// With no token yet, the daemon keeps retrying and doesn't exit; it stops only
// on a signal.
func TestRunUntilSignal_NoTokenKeepsRetrying(t *testing.T) {
	_, cfg := useTempLock(t)
	tokenMayArriveLater = true
	calls, mu := countingEnroll(1_000_000, enrollment.ErrNoToken)

	sig := make(chan os.Signal, 1)
	done := make(chan error, 1)
	p := NewProgram(cfg)
	go func() { done <- runUntilSignal(p, sig) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := *calls
		mu.Unlock()
		if n >= 3 {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("runUntilSignal returned %v while waiting for a token", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("enrollment tried %d times, want retries", n)
		}
		time.Sleep(5 * time.Millisecond)
	}

	sig <- syscall.SIGINT
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("runUntilSignal() = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runUntilSignal didn't stop on the signal")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.mainIntegration != nil {
		t.Error("the agent started without being enrolled")
	}
}

// A failed start returns at once instead of blocking on the signal channel,
// so launchd's KeepAlive (or systemd) can restart the process.
func TestRunUntilSignal_FailedStartReturns(t *testing.T) {
	lockPath, cfg := useTempLock(t)
	holder := lockfile.NewLockFileWithPath(lockPath)
	if err := holder.TryAcquire(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Release() }()

	done := make(chan error, 1)
	go func() { done <- runUntilSignal(NewProgram(cfg), make(chan os.Signal)) }()
	select {
	case err := <-done:
		if !errors.Is(err, lockfile.ErrAlreadyRunning) {
			t.Errorf("runUntilSignal() = %v, want ErrAlreadyRunning", err)
		}
		if got := StartExitCode(err); got != ExitAlreadyRunning {
			t.Errorf("StartExitCode = %d, want %d", got, ExitAlreadyRunning)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runUntilSignal blocked after a failed start")
	}
}

// The LaunchDaemon starts the agent in service mode, never with -run.
func TestLaunchdPlist_ServiceMode(t *testing.T) {
	plist := launchdPlist("1.2.3")
	if strings.Contains(plist, "<string>-run</string>") {
		t.Error("the LaunchDaemon still starts the agent with -run")
	}
	want := "<string>/opt/sentinelgo/sentinelgo</string>\n        <string>-config</string>\n        <string>/opt/sentinelgo/.sentinelgo/config.json</string>"
	if !strings.Contains(plist, want) {
		t.Errorf("ProgramArguments missing %q in:\n%s", want, plist)
	}
	if !strings.Contains(plist, "SentinelGo Agent v1.2.3") {
		t.Error("version missing from the plist comment")
	}
}

// The enrollment identity carries the Windows OMA-DM DeviceID and SMBIOS UUID
// from the MDM collector (#398), the macOS provisioning UDID, and prefers the
// collector's serial over the system one.
func TestIdentityFromMDM(t *testing.T) {
	win := &shared.MDMInfo{Identity: shared.MDMIdentity{
		OMADMDeviceID: "6F3A1C2B-0D4E-4F5A-9B8C-7D6E5F4A3B2C",
		SMBIOSUUID:    "4c4c4544-0042-3510-8052-b4c04f4e3132",
	}}
	got := identityFromMDM("SYS-SERIAL", win)
	want := enrollment.Identity{Serial: "SYS-SERIAL", OMADMDeviceID: win.Identity.OMADMDeviceID, SMBIOSUUID: win.Identity.SMBIOSUUID}
	if got != want {
		t.Errorf("windows: %+v, want %+v", got, want)
	}

	mac := &shared.MDMInfo{Identity: shared.MDMIdentity{Serial: "C02XYZ", ProvisioningUDID: "00008103-001A"}}
	if got := identityFromMDM("SYS-SERIAL", mac); got != (enrollment.Identity{Serial: "C02XYZ", ProvisioningUDID: "00008103-001A"}) {
		t.Errorf("macOS: %+v", got)
	}

	if got := identityFromMDM("SYS-SERIAL", nil); got != (enrollment.Identity{Serial: "SYS-SERIAL"}) {
		t.Errorf("no MDM info: %+v", got)
	}
}
