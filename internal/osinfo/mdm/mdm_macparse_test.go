package mdm

import (
	"testing"
	"time"

	"sentinelgo/internal/osinfo/shared"
)

func TestParseEnrollmentStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  string
		want enrollmentStatus
	}{
		{"ade, macOS 13+", "Enrolled via DEP: Yes\nMDM enrollment: Yes (User Approved)\nMDM server: https://mdm.example.com:8443/mdm/connect?t=secret\n",
			enrollmentStatus{known: true, enrolled: true, userApproved: true, viaDEP: true, serverURL: "https://mdm.example.com:8443/mdm/connect?t=secret"}},
		{"profile, not user approved", "Enrolled via DEP: No\nMDM enrollment: Yes\n",
			enrollmentStatus{known: true, enrolled: true}},
		{"not enrolled", "Enrolled via DEP: No\nMDM enrollment: No\n", enrollmentStatus{known: true}},
		{"profiles: prefix and CRLF", "profiles: Enrolled via DEP: No\r\nprofiles: MDM enrollment: Yes (User Approved)\r\n",
			enrollmentStatus{known: true, enrolled: true, userApproved: true}},
		{"empty (command failed)", "", enrollmentStatus{}},
	} {
		if got := parseEnrollmentStatus(tc.out); got != tc.want {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestParseADEConfig(t *testing.T) {
	assigned := `Device Enrollment configuration:
{
    AllowPairing = 1;
    AwaitDeviceConfigured = 0;
    ConfigurationURL = "https://mdm.example.com/mdm/enroll";
    IsMDMUnremovable = 1;
    IsSupervised = 1;
}`
	got := parseADEConfig(assigned)
	if got.assigned == nil || !*got.assigned || got.serverURL != "https://mdm.example.com/mdm/enroll" {
		t.Errorf("assigned: %+v", got)
	}
	got = parseADEConfig("Error fetching Device Enrollment configuration: Client is not DEP enabled.")
	if got.assigned == nil || *got.assigned {
		t.Errorf("not assigned: %+v", got)
	}
	if got = parseADEConfig("Error fetching Device Enrollment configuration - Request timed out"); got.assigned != nil {
		t.Errorf("a network error must be unknown, got %+v", got)
	}
}

func TestParseBootstrapToken(t *testing.T) {
	if b := parseBootstrapToken("profiles: Bootstrap Token supported on server: YES\nprofiles: Bootstrap Token escrowed to server: YES\n"); b == nil || !*b {
		t.Errorf("escrowed: %v", b)
	}
	if b := parseBootstrapToken("profiles: Bootstrap Token supported on server: YES\nprofiles: Bootstrap Token escrowed to server: NO\n"); b == nil || *b {
		t.Errorf("not escrowed: %v", b)
	}
	if b := parseBootstrapToken(""); b != nil {
		t.Errorf("no output: %v", *b)
	}
}

func TestParseHardwareIdentity(t *testing.T) {
	appleSilicon := `{"SPHardwareDataType":[{"serial_number":"C02XG0FDH7JY","platform_UUID":"8E2A3F2C-1111-2222-3333-444455556666","provisioning_UDID":"00008103-001A2B3C4D5E6F7A"}]}`
	id := parseHardwareIdentity(appleSilicon)
	if id.ProvisioningUDID != "00008103-001A2B3C4D5E6F7A" || id.HardwareUUID != "8E2A3F2C-1111-2222-3333-444455556666" || id.Serial != "C02XG0FDH7JY" {
		t.Errorf("apple silicon: %+v", id)
	}
	// Intel / older macOS: no provisioning UDID; MDM uses the hardware UUID.
	intel := `{"SPHardwareDataType":[{"serial_number":"C02ABC","platform_UUID":"564D1234-AAAA-BBBB-CCCC-DDDDEEEEFFFF"}]}`
	if id := parseHardwareIdentity(intel); id.ProvisioningUDID != "564D1234-AAAA-BBBB-CCCC-DDDDEEEEFFFF" {
		t.Errorf("intel fallback: %+v", id)
	}
	if id := parseHardwareIdentity("not json"); id != (shared.MDMIdentity{}) {
		t.Errorf("bad json: %+v", id)
	}
}

func TestBuildMacInfo(t *testing.T) {
	now := time.Date(2026, 11, 2, 10, 0, 0, 0, time.FixedZone("x", 3600))
	ade := enrollmentStatus{known: true, enrolled: true, userApproved: true, viaDEP: true, serverURL: "https://MDM.example.com/mdm/connect?token=abc"}

	info := buildMacInfo(ade, adeConfig{}, boolPtr(true), shared.MDMIdentity{Serial: "S"}, "mdm.example.com", now)
	if info.EnrollmentType != TypeADE || info.Supervised == nil || !*info.Supervised || info.ADEAssigned == nil || !*info.ADEAssigned {
		t.Errorf("ade: %+v", info)
	}
	if info.ServerURLHost != "mdm.example.com" || !info.IsOurServer {
		t.Errorf("server host %q ours=%v; want the host only, matched", info.ServerURLHost, info.IsOurServer)
	}
	if !info.CollectedAt.Equal(now) || info.CollectedAt.Location() != time.UTC {
		t.Errorf("collected_at = %v, want %v in UTC", info.CollectedAt, now)
	}

	// mdm_host given as a URL matches too; another host doesn't.
	if !buildMacInfo(ade, adeConfig{}, nil, shared.MDMIdentity{}, "https://mdm.example.com/", now).IsOurServer {
		t.Error("mdm_host as a URL didn't match")
	}
	if buildMacInfo(ade, adeConfig{}, nil, shared.MDMIdentity{}, "mdm.other.com", now).IsOurServer {
		t.Error("another MDM counted as ours")
	}
	if buildMacInfo(ade, adeConfig{}, nil, shared.MDMIdentity{}, "", now).IsOurServer {
		t.Error("unconfigured mdm_host counted as ours")
	}

	profile := enrollmentStatus{known: true, enrolled: true, userApproved: true}
	if info := buildMacInfo(profile, adeConfig{assigned: boolPtr(false)}, nil, shared.MDMIdentity{}, "", now); info.EnrollmentType != TypeProfile || *info.Supervised || *info.ADEAssigned {
		t.Errorf("profile: %+v", info)
	}

	none := enrollmentStatus{known: true}
	info = buildMacInfo(none, adeConfig{assigned: boolPtr(true), serverURL: "https://mdm.example.com/enroll"}, nil, shared.MDMIdentity{}, "", now)
	if info.EnrollmentType != TypeNone || info.Enrolled || !*info.ADEAssigned || info.ADEServerHost != "mdm.example.com" {
		t.Errorf("assigned but not enrolled: %+v", info)
	}

	if info := buildMacInfo(enrollmentStatus{}, adeConfig{}, nil, shared.MDMIdentity{}, "", now); info.EnrollmentType != TypeUnknown || info.Supervised != nil {
		t.Errorf("unknown: %+v", info)
	}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{
		"https://mdm.example.com:8443/mdm/connect?t=1": "mdm.example.com",
		"  https://MDM.Example.com/  ":                 "mdm.example.com",
		"mdm.example.com":                              "", // not a URL
		"":                                             "",
	} {
		if got := hostOf(in); got != want {
			t.Errorf("hostOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func FuzzMacParsers(f *testing.F) {
	f.Add("Enrolled via DEP: Yes\nMDM enrollment: Yes (User Approved)\nMDM server: https://x/y")
	f.Add(`ConfigurationURL = "https://x/enroll";`)
	f.Add(`{"SPHardwareDataType":[{"provisioning_UDID":"u"}]}`)
	f.Fuzz(func(t *testing.T, s string) {
		st := parseEnrollmentStatus(s)
		info := buildMacInfo(st, parseADEConfig(s), parseBootstrapToken(s), parseHardwareIdentity(s), "x", time.Unix(0, 0))
		if info == nil || info.EnrollmentType == "" {
			t.Fatalf("no info for %q", s)
		}
	})
}
