package mdm

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

// fakeTools stubs the commands collect runs and counts `profiles show`.
func fakeTools(t *testing.T, status, show string) *int {
	t.Helper()
	shows := 0
	prevRun, prevOut, prevNow, prevOpen := runCommand, runCommandOutput, now, openFile
	openFile = func(string) (*os.File, error) {
		return nil, &fs.PathError{Op: "open", Path: tccDB, Err: fs.ErrPermission}
	}
	t.Cleanup(func() {
		runCommand, runCommandOutput, now, openFile = prevRun, prevOut, prevNow, prevOpen
		adeCache.at, adeCache.cfg = time.Time{}, adeConfig{}
	})
	adeCache.at, adeCache.cfg = time.Time{}, adeConfig{}
	runCommand = func(name string, args ...string) (string, error) {
		switch strings.Join(append([]string{name}, args...), " ") {
		case "profiles status -type enrollment":
			return status, nil
		case "profiles status -type bootstraptoken":
			return "profiles: Bootstrap Token escrowed to server: NO\n", nil
		case "system_profiler SPHardwareDataType -json":
			return `{"SPHardwareDataType":[{"serial_number":"S1","platform_UUID":"H1","provisioning_UDID":"P1"}]}`, nil
		case "profiles -C -o stdout-xml":
			return `<dict><key>PayloadType</key><string>com.apple.security.firewall</string></dict>`, nil
		}
		t.Errorf("unexpected command %s %v", name, args)
		return "", nil
	}
	runCommandOutput = func(name string, args ...string) (string, int, error) {
		shows++
		return show, 1, nil
	}
	return &shows
}

func TestCollect_NotEnrolled_CachesADELookup(t *testing.T) {
	shows := fakeTools(t, "Enrolled via DEP: No\nMDM enrollment: No\n", "Client is not DEP enabled.")
	base := time.Unix(1_800_000_000, 0)
	now = func() time.Time { return base }

	info := collect("mdm.example.com")
	if info.Enrolled || info.EnrollmentType != TypeNone || info.ADEAssigned == nil || *info.ADEAssigned {
		t.Fatalf("info = %+v", info)
	}
	if info.Identity.ProvisioningUDID != "P1" || info.BootstrapTokenEscrowed == nil || *info.BootstrapTokenEscrowed {
		t.Errorf("identity/bootstrap = %+v / %v", info.Identity, info.BootstrapTokenEscrowed)
	}

	collect("mdm.example.com")
	if *shows != 1 {
		t.Errorf("profiles show ran %d times within the refresh window, want 1", *shows)
	}
	now = func() time.Time { return base.Add(adeRefresh + time.Minute) }
	collect("mdm.example.com")
	if *shows != 2 {
		t.Errorf("profiles show ran %d times after the refresh window, want 2", *shows)
	}
}

func TestCollect_UnknownADEIsRetried(t *testing.T) {
	shows := fakeTools(t, "Enrolled via DEP: No\nMDM enrollment: No\n", "Error: the request timed out")
	collect("")
	collect("")
	if *shows != 2 {
		t.Errorf("an unknown ADE result was cached (%d lookups, want 2)", *shows)
	}
}

func TestCollect_ADEEnrolledSkipsLookup(t *testing.T) {
	shows := fakeTools(t, "Enrolled via DEP: Yes\nMDM enrollment: Yes (User Approved)\nMDM server: https://mdm.example.com/mdm\n", "")
	info := collect("mdm.example.com")
	if *shows != 0 {
		t.Error("asked Apple about ADE for a Mac already enrolled through ADE")
	}
	if !info.IsOurServer || info.EnrollmentType != TypeADE {
		t.Errorf("info = %+v", info)
	}
}

// Managed settings come from the installed profiles; without Full Disk
// Access the grant is reported false.
func TestCollect_ManagedSettingsAndFullDiskAccess(t *testing.T) {
	fakeTools(t, "Enrolled via DEP: No\nMDM enrollment: Yes (User Approved)\n", "Client is not DEP enabled.")
	info := collect("")
	if !slices.Equal(info.ManagedSettings, []string{"firewall"}) || !slices.Equal(info.ProfilePayloadTypes, []string{"com.apple.security.firewall"}) {
		t.Errorf("managed = %v, payloads = %v", info.ManagedSettings, info.ProfilePayloadTypes)
	}
	if fda := info.Grants.FullDiskAccess; fda == nil || *fda {
		t.Errorf("full disk access = %v, want false", fda)
	}
	openFile = func(string) (*os.File, error) { return nil, fs.ErrNotExist }
	if fda := collect("").Grants.FullDiskAccess; fda != nil {
		t.Errorf("missing TCC.db: full disk access = %v, want unknown", *fda)
	}
}

// The agent block carries the signature and the Full Disk Access state,
// which is checked again on every inventory (#339).
func TestCollect_AgentBlock(t *testing.T) {
	fakeTools(t, "Enrolled via DEP: No\nMDM enrollment: No\n", "Client is not DEP enabled.")
	prevSig := codeSignature
	t.Cleanup(func() { codeSignature = prevSig })
	team := "ABCDE12345"
	want := &shared.AgentCodeSignature{Path: "/opt/sentinelgo/SentinelGo.app", Signature: SigDeveloperID, TeamID: &team}
	codeSignature = func() *shared.AgentCodeSignature { return want }

	info := collect("")
	if info.Agent == nil || info.Agent.CodeSignature != want || info.Agent.FullDiskAccess != FDADenied {
		t.Fatalf("agent = %+v", info.Agent)
	}
	openFile = func(string) (*os.File, error) { return os.Open(os.DevNull) }
	if got := collect("").Agent.FullDiskAccess; got != FDAGranted {
		t.Errorf("after a grant: full_disk_access = %q, want granted", got)
	}
}

// The real Security framework on the test binary: `go test` binaries are
// linker-signed ad hoc on Apple silicon and unsigned on Intel, never
// Developer ID.
func TestSelfSignature_Real(t *testing.T) {
	if err := loadSecurity(); err != nil {
		t.Fatalf("loadSecurity: %v", err)
	}
	sig := readSelfSignature()
	if sig == nil {
		t.Fatal("readSelfSignature returned nil")
	}
	exe, _ := os.Executable()
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	if sig.Path != exe {
		t.Errorf("path = %q, want the test executable %q", sig.Path, exe)
	}
	if sig.TeamID != nil {
		t.Errorf("team_id = %q on a test binary", *sig.TeamID)
	}
	switch sig.Signature {
	case SigAdhoc:
		if sig.Identifier == nil || *sig.Identifier == "" {
			t.Error("ad-hoc signature without an identifier")
		}
		if sig.DesignatedRequirement == nil || !strings.Contains(*sig.DesignatedRequirement, "cdhash") {
			t.Errorf("designated requirement = %v, want an implicit cdhash requirement", sig.DesignatedRequirement)
		}
	case SigUnsigned:
		if sig.Identifier != nil || sig.DesignatedRequirement != nil {
			t.Errorf("unsigned but identifier = %v, requirement = %v", sig.Identifier, sig.DesignatedRequirement)
		}
	default:
		t.Errorf("signature = %q, want adhoc or unsigned for a go test binary", sig.Signature)
	}
	t.Logf("signature: %s, identifier: %v, requirement: %v", sig.Signature, deref(sig.Identifier), deref(sig.DesignatedRequirement))
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
