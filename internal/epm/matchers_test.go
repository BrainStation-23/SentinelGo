package epm

import (
	"regexp"
	"runtime"
	"testing"
	"time"
)

// TestDefaultMatchers_CoversEveryConditionKind proves the registry has no
// gaps: every ConditionKind declared in condition.go must have a Matcher, or
// a hand-authored bundle referencing it would fail to compile with a
// confusing "unknown condition kind" error despite the kind being a real,
// documented part of the vocabulary.
func TestDefaultMatchers_CoversEveryConditionKind(t *testing.T) {
	allKinds := []ConditionKind{
		CondPath, CondFileName, CondSHA256, CondSHA1, CondScriptSHA256,
		CondPublisher, CondSigned, CondProductName, CondMSIProductCode,
		CondBundleID, CondPackageName,
		CondCommandLine, CondArgs, CondServiceName, CondParentProcess, CondChildProcess,
		CondUser, CondUserSID, CondUserGroup,
		CondDeviceGroup, CondOrg, CondDepartment, CondDomainJoined, CondEntraJoined,
		CondDiskEncryption, CondSecureBoot, CondFirewall, CondAntivirus, CondCompliance,
		CondNetworkType, CondVPNActive, CondCorporateNetwork,
		CondBusinessHours, CondDayOfWeek,
		CondOSType, CondOSVersion,
	}
	reg := DefaultMatchers()
	for _, k := range allKinds {
		if _, ok := reg.Lookup(k); !ok {
			t.Errorf("no Matcher registered for %q", k)
		}
	}
}

func TestMatcherRegistry_RejectsDuplicateRegistration(t *testing.T) {
	reg := NewMatcherRegistry()
	if err := reg.Register(pathMatcher{}); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := reg.Register(pathMatcher{}); err == nil {
		t.Error("expected an error registering the same Kind twice")
	}
}

// --- Always-known matchers (v1-parity: see matchers_identity.go doc comments) ---

func TestMatchers_AlwaysKnownEvenWhenEmpty(t *testing.T) {
	empty := &EvalInput{}
	tests := []struct {
		name string
		m    Matcher
	}{
		{"path", pathMatcher{}},
		{"file_name", fileNameMatcher{}},
		{"sha256", sha256Matcher{}},
		{"script_sha256", scriptSHA256Matcher{}},
		{"publisher", publisherMatcher{}},
		{"args", argsMatcher{}},
		{"service_name", serviceNameMatcher{}},
		{"user", userMatcher{}},
		{"os_type", osTypeMatcher{}},
		{"day_of_week", dayOfWeekMatcher{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, known := tc.m.Extract(empty)
			if !known {
				t.Errorf("%s.Extract on an empty EvalInput reported known=false; must be always-known "+
					"(v1's equivalent comparison is unconditional — see matchers_identity.go)", tc.name)
			}
		})
	}
}

func TestPathMatcher_ExtractNormalizesSeparators(t *testing.T) {
	in := &EvalInput{Request: ElevationRequestV2{AppPath: `C:\apps\tool.exe`}}
	vals, known := pathMatcher{}.Extract(in)
	if !known || len(vals) != 1 || vals[0] != "C:/apps/tool.exe" {
		t.Errorf("Extract = %v, %v, want [\"C:/apps/tool.exe\"], true", vals, known)
	}
}

func TestFileNameMatcher_ExtractsLastSegment(t *testing.T) {
	in := &EvalInput{Request: ElevationRequestV2{AppPath: `C:\apps\sub\tool.exe`}}
	vals, known := fileNameMatcher{}.Extract(in)
	if !known || len(vals) != 1 || vals[0] != "tool.exe" {
		t.Errorf("Extract = %v, %v, want [\"tool.exe\"], true", vals, known)
	}
}

func TestSHA256Matcher_DoesNotFoldCase(t *testing.T) {
	// See sha256Matcher's doc comment: v1 compares raw, case-sensitive.
	in := &EvalInput{Request: ElevationRequestV2{AppHash: "ABCDEF"}}
	vals, known := sha256Matcher{}.Extract(in)
	if !known || vals[0] != "ABCDEF" {
		t.Errorf("Extract = %v, %v, want [\"ABCDEF\"] (unmodified case), true", vals, known)
	}
}

func TestServiceNameMatcher_FoldsCaseOnlyOnWindows(t *testing.T) {
	in := &EvalInput{Request: ElevationRequestV2{RequestedServiceName: "MyService"}}
	vals, known := serviceNameMatcher{}.Extract(in)
	if !known {
		t.Fatal("expected known=true")
	}
	want := "MyService"
	if runtime.GOOS == "windows" {
		want = "myservice"
	}
	if vals[0] != want {
		t.Errorf("Extract = %v, want [%q] for GOOS=%s", vals, want, runtime.GOOS)
	}
}

func TestServiceNameMatcher_EmptyIsKnownFalseMatch(t *testing.T) {
	// Not Unknown: an empty extracted service name is a legitimate value that
	// simply fails to equal any specific authored requirement. See the
	// matcher's doc comment for why this distinction is load-bearing.
	in := &EvalInput{Request: ElevationRequestV2{RequestedServiceName: ""}}
	vals, known := serviceNameMatcher{}.Extract(in)
	if !known || vals[0] != "" {
		t.Errorf("Extract = %v, %v, want [\"\"], true", vals, known)
	}
}

// --- Matchers with no current producer: must report Unknown when empty ---

func TestMatchers_UnknownWhenNoProducer(t *testing.T) {
	empty := &EvalInput{}
	tests := []struct {
		name string
		m    Matcher
	}{
		{"sha1", sha1Matcher{}},
		{"signed", signedMatcher{}},
		{"product_name", productNameMatcher{}},
		{"msi_product_code", msiProductCodeMatcher{}},
		{"bundle_id", bundleIDMatcher{}},
		{"package_name", packageNameMatcher{}},
		{"command_line", commandLineMatcher{}},
		{"parent_process", parentProcessMatcher{}},
		{"child_process", childProcessMatcher{}},
		{"user_sid", userSIDMatcher{}},
		{"user_group", userGroupMatcher{}},
		{"device_group", deviceGroupMatcher{}},
		{"org", orgMatcher{}},
		{"department", departmentMatcher{}},
		{"domain_joined", domainJoinedMatcher{}},
		{"entra_joined", entraJoinedMatcher{}},
		{"disk_encryption", diskEncryptionMatcher{}},
		{"secure_boot", secureBootMatcher{}},
		{"firewall", firewallMatcher{}},
		{"antivirus", antivirusMatcher{}},
		{"compliance", complianceMatcher{}},
		{"network_type", networkTypeMatcher{}},
		{"vpn_active", vpnActiveMatcher{}},
		{"corporate_network", corporateNetworkMatcher{}},
		{"os_version", osVersionMatcher{}},
		{"business_hours (no policy configured)", businessHoursMatcher{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, known := tc.m.Extract(empty)
			if known {
				t.Errorf("%s.Extract on an empty EvalInput reported known=true; should be Unknown "+
					"until a collector or the transport populates it", tc.name)
			}
		})
	}
}

// --- Context matchers: known once populated AND fresh, unknown once stale ---

func TestContextMatchers_KnownWhenFreshAndPopulated(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	in := &EvalInput{
		Now: now,
		Context: ContextSnapshot{
			DiskEncryption:   "encrypted",
			SecureBoot:       "enabled",
			FirewallState:    "enabled",
			AntivirusHealth:  "healthy",
			Compliance:       "compliant",
			NetworkType:      "wired",
			VPNActive:        TriTrue,
			CorporateNetwork: TriTrue,
			DomainJoined:     TriTrue,
			EntraJoined:      TriFalse,
			OSVersion:        "10.0.19045",
			Sources: map[string]SourceState{
				"posture": {CollectedAt: now, OK: true},
				"network": {CollectedAt: now, OK: true},
				"join":    {CollectedAt: now, OK: true},
			},
		},
	}

	tests := []struct {
		name string
		m    Matcher
	}{
		{"disk_encryption", diskEncryptionMatcher{}}, {"secure_boot", secureBootMatcher{}},
		{"firewall", firewallMatcher{}}, {"antivirus", antivirusMatcher{}},
		{"compliance", complianceMatcher{}}, {"network_type", networkTypeMatcher{}},
		{"vpn_active", vpnActiveMatcher{}}, {"corporate_network", corporateNetworkMatcher{}},
		{"domain_joined", domainJoinedMatcher{}}, {"entra_joined", entraJoinedMatcher{}},
		{"os_version", osVersionMatcher{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, known := tc.m.Extract(in)
			if !known {
				t.Errorf("%s.Extract reported Unknown despite a fresh, populated snapshot", tc.name)
			}
		})
	}
}

func TestContextMatchers_UnknownWhenStale(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	stale := now.Add(-2 * time.Hour) // well beyond contextPostureMaxAge/contextNetworkMaxAge
	in := &EvalInput{
		Now: now,
		Context: ContextSnapshot{
			DiskEncryption: "encrypted",
			NetworkType:    "wired",
			Sources: map[string]SourceState{
				"posture": {CollectedAt: stale, OK: true},
				"network": {CollectedAt: stale, OK: true},
			},
		},
	}
	var diskM diskEncryptionMatcher
	if _, known := diskM.Extract(in); known {
		t.Error("disk_encryption should be Unknown when its source is stale")
	}
	var netM networkTypeMatcher
	if _, known := netM.Extract(in); known {
		t.Error("network_type should be Unknown when its source is stale")
	}
}

func TestContextMatchers_UnknownWhenSourceFailed(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	in := &EvalInput{
		Now: now,
		Context: ContextSnapshot{
			DiskEncryption: "encrypted",
			Sources: map[string]SourceState{
				"posture": {CollectedAt: now, OK: false, Err: "collector panicked"},
			},
		},
	}
	var diskM diskEncryptionMatcher
	if _, known := diskM.Extract(in); known {
		t.Error("disk_encryption should be Unknown when its source reported a failure")
	}
}

func TestPosturalValue_ReportsUnknownForCollectorReportedUnknown(t *testing.T) {
	// A collector that itself could not determine the value (reports the
	// literal string "unknown") must not be treated as a confident answer.
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	in := &EvalInput{
		Now: now,
		Context: ContextSnapshot{
			SecureBoot: "unknown",
			Sources:    map[string]SourceState{"posture": {CollectedAt: now, OK: true}},
		},
	}
	var sbM secureBootMatcher
	if _, known := sbM.Extract(in); known {
		t.Error("a collector-reported \"unknown\" value must not be treated as known")
	}
}

// --- Time matchers ---

func TestBusinessHoursMatcher_NoPolicyConfiguredIsUnknown(t *testing.T) {
	in := &EvalInput{Now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	var bhM businessHoursMatcher
	if _, known := bhM.Extract(in); known {
		t.Error("business_hours must be Unknown (not false) when no Defaults are configured")
	}
}

func TestBusinessHoursMatcher_InsideAndOutsideWindow(t *testing.T) {
	// 2026-01-01 is a Thursday.
	in := &EvalInput{
		Now: time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC),
		Defaults: TimeDefaults{
			BusinessHoursStart: "09:00", BusinessHoursEnd: "17:00",
			BusinessDays: []string{"Mon", "Tue", "Wed", "Thu", "Fri"},
		},
	}
	vals, known := businessHoursMatcher{}.Extract(in)
	if !known || vals[0] != "true" {
		t.Errorf("10:00 on a Thursday inside 09:00-17:00 Mon-Fri = %v, %v, want [\"true\"], true", vals, known)
	}

	in.Now = time.Date(2026, 1, 1, 20, 0, 0, 0, time.UTC) // still Thursday, after hours
	vals, known = businessHoursMatcher{}.Extract(in)
	if !known || vals[0] != "false" {
		t.Errorf("20:00 on a Thursday = %v, %v, want [\"false\"], true", vals, known)
	}

	in.Now = time.Date(2026, 1, 3, 10, 0, 0, 0, time.UTC) // Saturday, within hours but wrong day
	vals, known = businessHoursMatcher{}.Extract(in)
	if !known || vals[0] != "false" {
		t.Errorf("10:00 on a Saturday = %v, %v, want [\"false\"], true", vals, known)
	}
}

func TestDayOfWeekMatcher(t *testing.T) {
	in := &EvalInput{Now: time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)} // Thursday
	vals, known := dayOfWeekMatcher{}.Extract(in)
	if !known || vals[0] != "Thu" {
		t.Errorf("Extract = %v, %v, want [\"Thu\"], true", vals, known)
	}
}

func TestOSTypeMatcher_MatchesRuntimeGOOS(t *testing.T) {
	vals, known := osTypeMatcher{}.Extract(&EvalInput{})
	if !known || vals[0] != runtime.GOOS {
		t.Errorf("Extract = %v, %v, want [%q], true", vals, known, runtime.GOOS)
	}
}

// --- applyOperator (compile.go) ---

func TestApplyOperator(t *testing.T) {
	tests := []struct {
		op     Operator
		value  string
		values []string
		ev     string
		want   bool
	}{
		{OpEquals, "abc", nil, "abc", true},
		{OpEquals, "abc", nil, "abd", false},
		{OpIn, "", []string{"a", "b", "c"}, "b", true},
		{OpIn, "", []string{"a", "b", "c"}, "z", false},
		{OpGlob, "C:/apps/*/tool.exe", nil, "C:/apps/sub/tool.exe", true},
		{OpGlob, "C:/apps/*/tool.exe", nil, "C:/apps/tool.exe", false},
		{OpPrefix, "C:/apps/", nil, "C:/apps/tool.exe", true},
		{OpPrefix, "C:/apps/", nil, "D:/apps/tool.exe", false},
		{OpSuffix, ".exe", nil, "tool.exe", true},
		{OpSuffix, ".exe", nil, "tool.dll", false},
		{OpContains, "app", nil, "myapplication", true},
		{OpContains, "zzz", nil, "myapplication", false},
		{OpVersionGTE, "10.0", nil, "10.5", true},
		{OpVersionGTE, "10.0", nil, "9.9", false},
		{OpVersionLT, "10.0", nil, "9.9", true},
		{OpVersionLT, "10.0", nil, "10.0", false},
		{OpBetween, "", []string{"9.0", "11.0"}, "10.5", true},
		{OpBetween, "", []string{"9.0", "11.0"}, "12.0", false},
		{OpBetween, "", []string{"09:00", "17:00"}, "12:00", true},
		{OpBetween, "", []string{"09:00", "17:00"}, "20:00", false},
		{OpIsTrue, "", nil, "true", true},
		{OpIsTrue, "", nil, "false", false},
		{OpIsFalse, "", nil, "false", true},
		{OpIsFalse, "", nil, "true", false},
	}
	for _, tc := range tests {
		got := applyOperator(tc.op, tc.value, tc.values, nil, tc.ev)
		if got != tc.want {
			t.Errorf("applyOperator(%s, value=%q, values=%v, ev=%q) = %v, want %v",
				tc.op, tc.value, tc.values, tc.ev, got, tc.want)
		}
	}
}

func TestApplyOperator_Regex(t *testing.T) {
	re := regexp.MustCompile(`^C:/apps/.*\.exe$`)
	if !applyOperator(OpRegex, "", nil, re, "C:/apps/tool.exe") {
		t.Error("expected regex match")
	}
	if applyOperator(OpRegex, "", nil, re, "C:/apps/tool.dll") {
		t.Error("expected regex non-match")
	}
	if applyOperator(OpRegex, "", nil, nil, "anything") {
		t.Error("a nil compiled regex (should never happen post-Compile) must not match")
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"10.5", "10.0.9", 1},
		{"10.0.9", "9.9.9", 1},
		{"1.2.3", "1.2.3", 0},
		{"1.2", "1.2.0", 0},
		{"2.0", "10.0", -1}, // numeric, not lexical: 2 < 10
		{"1.x", "1.0", 0},   // non-numeric segment treated as 0
	}
	for _, tc := range tests {
		if got := compareVersions(tc.a, tc.b); sign(got) != sign(tc.want) {
			t.Errorf("compareVersions(%q, %q) = %d, want sign %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}
