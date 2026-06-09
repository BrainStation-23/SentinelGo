package system

// system_test.go has no OS-specific file suffix, so every test runs on every
// platform. All functions under test live in parse.go which is also suffix-free.

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// ── parseOSQueryVersion ───────────────────────────────────────────────────────

func TestParseOSQueryVersion(t *testing.T) {
	cases := []struct{ input, want string }{
		{"osqueryi version 5.5.1\n", "5.5.1"},
		{"osquery version 5.0.1", "5.0.1"},
		{"osqueryi version 5.11.0\r\n", "5.11.0"},
		// version keyword appears after other tokens
		{"osquery\nosquery version 4.9.0\n", "4.9.0"},
	}
	for _, c := range cases {
		if got := parseOSQueryVersion(c.input); got != c.want {
			t.Errorf("parseOSQueryVersion(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestParseOSQueryVersion_NoVersionKeyword(t *testing.T) {
	// "version" keyword absent — cannot extract anything
	if got := parseOSQueryVersion("osqueryi 5.5.1"); got != "" {
		t.Errorf("expected empty without 'version' keyword, got %q", got)
	}
}

func TestParseOSQueryVersion_Empty(t *testing.T) {
	if got := parseOSQueryVersion(""); got != "" {
		t.Errorf("expected empty for empty input, got %q", got)
	}
}

// ── parseBootRelative ─────────────────────────────────────────────────────────

func TestParseBootRelative(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{48 * time.Hour, "2 days ago"},
		{25 * time.Hour, "1 days ago"},
		{3*time.Hour + 30*time.Minute, "3 hours ago"},
		{1*time.Hour + 59*time.Minute, "1 hours ago"},
		{45 * time.Minute, "45 minutes ago"},
		{1 * time.Minute, "1 minutes ago"},
		{59 * time.Second, "Recently"},
		{0, "Recently"},
	}
	for _, c := range cases {
		if got := parseBootRelative(c.d); got != c.want {
			t.Errorf("parseBootRelative(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}

func TestParseBootRelative_DaysBoundary(t *testing.T) {
	// Exactly 24 hours is 1 day, not 24 hours
	if got := parseBootRelative(24 * time.Hour); got != "1 days ago" {
		t.Errorf("parseBootRelative(24h) = %q, want '1 days ago'", got)
	}
	// 23h 59m is hours, not days
	if got := parseBootRelative(23*time.Hour + 59*time.Minute); !strings.HasSuffix(got, "hours ago") {
		t.Errorf("parseBootRelative(23h59m) = %q, want '<N> hours ago'", got)
	}
}

// ── parseBatteryStatusCode ────────────────────────────────────────────────────

func TestParseBatteryStatusCode(t *testing.T) {
	cases := []struct{ code, want string }{
		{"1", "Discharging"},
		{"2", "AC Power"},
		{"3", "Fully Charged"},
		{"4", "Low"},
		{"5", "Critical"},
		{"6", "Charging"},
		{"7", "Undefined"},
		{"8", ""}, // unrecognised — caller decides fallback
		{"0", ""},
		{"", ""},
		{" 3 \n", "Fully Charged"}, // whitespace trimmed
	}
	for _, c := range cases {
		if got := parseBatteryStatusCode(c.code); got != c.want {
			t.Errorf("parseBatteryStatusCode(%q) = %q, want %q", c.code, got, c.want)
		}
	}
}

// ── parseWindowsChassisCode ───────────────────────────────────────────────────

func TestParseWindowsChassisCode(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{3, "Desktop"}, {7, "Desktop"}, {15, "Desktop"}, {16, "Desktop"},
		{8, "Notebook"}, {12, "Notebook"}, {14, "Notebook"}, {21, "Notebook"},
		{17, "Server"}, {23, "Server"},
		{30, "Tablet"}, {31, "Tablet"}, {32, "Tablet"},
		{0, ""}, // unrecognised
		{1, ""},
		{2, ""},
		{99, ""},
	}
	for _, c := range cases {
		if got := parseWindowsChassisCode(c.n); got != c.want {
			t.Errorf("parseWindowsChassisCode(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

// ── parseWindowsOSInfoJSON ────────────────────────────────────────────────────

const winOSInfoJSON = `{"Caption":"Microsoft Windows 11 Pro","Version":"10.0.22000","BuildNumber":"22000"}`

func TestParseWindowsOSInfoJSON(t *testing.T) {
	name, version, build := parseWindowsOSInfoJSON(winOSInfoJSON)
	if name != "Microsoft Windows 11 Pro" {
		t.Errorf("name = %q, want 'Microsoft Windows 11 Pro'", name)
	}
	if version != "10.0.22000" {
		t.Errorf("version = %q, want '10.0.22000'", version)
	}
	if build != "22000" {
		t.Errorf("build = %q, want '22000'", build)
	}
}

func TestParseWindowsOSInfoJSON_NumericBuildNumber(t *testing.T) {
	// PowerShell may encode BuildNumber as a JSON number
	name, _, build := parseWindowsOSInfoJSON(`{"Caption":"Windows 10","BuildNumber":19045}`)
	if name != "Windows 10" {
		t.Errorf("name = %q, want 'Windows 10'", name)
	}
	if build == "" {
		t.Error("build should be non-empty for numeric BuildNumber")
	}
}

func TestParseWindowsOSInfoJSON_MissingFields(t *testing.T) {
	name, version, build := parseWindowsOSInfoJSON(`{"Caption":"Windows 10"}`)
	if name != "Windows 10" {
		t.Errorf("name = %q, want 'Windows 10'", name)
	}
	if version != "" || build != "" {
		t.Errorf("absent fields should be empty: version=%q build=%q", version, build)
	}
}

func TestParseWindowsOSInfoJSON_Invalid(t *testing.T) {
	name, version, build := parseWindowsOSInfoJSON("not json")
	if name != "" || version != "" || build != "" {
		t.Errorf("expected all empty for invalid JSON, got name=%q version=%q build=%q", name, version, build)
	}
}

// ── parseWindowsOSInfoExtendedJSON ────────────────────────────────────────────

const winOSInfoExtendedJSON = `{
  "Caption":        "Microsoft Windows 11 Enterprise",
  "Version":        "10.0.26200.8524",
  "DisplayVersion": "25H2",
  "Locale":         "en-US",
  "Language":       "en-US",
  "TimeZoneId":     "Bangladesh Standard Time",
  "TimeZoneOffset": 360
}`

func TestParseWindowsOSInfoExtendedJSON(t *testing.T) {
	name, version, displayVer, locale, language, tzID, tzOffset :=
		parseWindowsOSInfoExtendedJSON(winOSInfoExtendedJSON)

	if name != "Microsoft Windows 11 Enterprise" {
		t.Errorf("name = %q, want 'Microsoft Windows 11 Enterprise'", name)
	}
	if version != "10.0.26200.8524" {
		t.Errorf("version = %q, want '10.0.26200.8524'", version)
	}
	if displayVer != "25H2" {
		t.Errorf("displayVersion = %q, want '25H2'", displayVer)
	}
	if locale != "en-US" {
		t.Errorf("locale = %q, want 'en-US'", locale)
	}
	if language != "en-US" {
		t.Errorf("language = %q, want 'en-US'", language)
	}
	if tzID != "Bangladesh Standard Time" {
		t.Errorf("tzID = %q, want 'Bangladesh Standard Time'", tzID)
	}
	if tzOffset != 360 {
		t.Errorf("tzOffset = %d, want 360", tzOffset)
	}
}

func TestParseWindowsOSInfoExtendedJSON_NegativeOffset(t *testing.T) {
	// UTC-5 (e.g. Eastern Standard Time)
	const input = `{"Caption":"Windows 11","Version":"10.0.22631.1000","DisplayVersion":"23H2",` +
		`"Locale":"en-US","Language":"en-US","TimeZoneId":"Eastern Standard Time","TimeZoneOffset":-300}`
	_, _, _, _, _, tzID, tzOffset := parseWindowsOSInfoExtendedJSON(input)
	if tzID != "Eastern Standard Time" {
		t.Errorf("tzID = %q, want 'Eastern Standard Time'", tzID)
	}
	if tzOffset != -300 {
		t.Errorf("tzOffset = %d, want -300", tzOffset)
	}
}

func TestParseWindowsOSInfoExtendedJSON_MissingFields(t *testing.T) {
	name, version, displayVer, locale, language, tzID, tzOffset :=
		parseWindowsOSInfoExtendedJSON(`{"Caption":"Windows 10"}`)
	if name != "Windows 10" {
		t.Errorf("name = %q, want 'Windows 10'", name)
	}
	if version != "" || displayVer != "" || locale != "" || language != "" || tzID != "" {
		t.Errorf("absent string fields should be empty: version=%q displayVer=%q locale=%q language=%q tzID=%q",
			version, displayVer, locale, language, tzID)
	}
	if tzOffset != 0 {
		t.Errorf("absent tzOffset should be 0, got %d", tzOffset)
	}
}

func TestParseWindowsOSInfoExtendedJSON_InvalidJSON(t *testing.T) {
	name, version, displayVer, locale, language, tzID, tzOffset :=
		parseWindowsOSInfoExtendedJSON("not json")
	if name != "" || version != "" || displayVer != "" || locale != "" ||
		language != "" || tzID != "" || tzOffset != 0 {
		t.Error("expected all zero values for invalid JSON")
	}
}

func TestParseWindowsOSInfoExtendedJSON_CompressedOutput(t *testing.T) {
	// ConvertTo-Json -Compress emits a single line — verify parser handles it.
	const input = `{"Caption":"Microsoft Windows 11 Pro","Version":"10.0.22631.4169","DisplayVersion":"23H2","Locale":"fr-FR","Language":"fr-FR","TimeZoneId":"Romance Standard Time","TimeZoneOffset":60}`
	name, version, _, locale, _, tzID, tzOffset := parseWindowsOSInfoExtendedJSON(input)
	if name != "Microsoft Windows 11 Pro" {
		t.Errorf("name = %q", name)
	}
	if version != "10.0.22631.4169" {
		t.Errorf("version = %q", version)
	}
	if locale != "fr-FR" {
		t.Errorf("locale = %q", locale)
	}
	if tzID != "Romance Standard Time" {
		t.Errorf("tzID = %q", tzID)
	}
	if tzOffset != 60 {
		t.Errorf("tzOffset = %d, want 60", tzOffset)
	}
}

// ── parseOSReleaseContent ─────────────────────────────────────────────────────

const osReleaseSample = `NAME="Ubuntu"
VERSION="22.04 LTS (Jammy Jellyfish)"
ID=ubuntu
PRETTY_NAME="Ubuntu 22.04 LTS"
VERSION_ID="22.04"
`

func TestParseOSReleaseContent(t *testing.T) {
	name, version := parseOSReleaseContent(osReleaseSample)
	if name != "Ubuntu 22.04 LTS" {
		t.Errorf("name = %q, want 'Ubuntu 22.04 LTS'", name)
	}
	if version != "22.04 LTS (Jammy Jellyfish)" {
		t.Errorf("version = %q, want '22.04 LTS (Jammy Jellyfish)'", version)
	}
}

func TestParseOSReleaseContent_UnquotedValues(t *testing.T) {
	input := "PRETTY_NAME=Alpine Linux v3.18\nVERSION=3.18.0\n"
	name, version := parseOSReleaseContent(input)
	if name != "Alpine Linux v3.18" {
		t.Errorf("name = %q, want 'Alpine Linux v3.18'", name)
	}
	if version != "3.18.0" {
		t.Errorf("version = %q, want '3.18.0'", version)
	}
}

func TestParseOSReleaseContent_Empty(t *testing.T) {
	name, version := parseOSReleaseContent("")
	if name != "" || version != "" {
		t.Errorf("expected empty results for empty input, got name=%q version=%q", name, version)
	}
}

func TestParseOSReleaseContent_NoPrettyName(t *testing.T) {
	// VERSION present but no PRETTY_NAME
	_, version := parseOSReleaseContent("NAME=Debian\nVERSION=12 (bookworm)\n")
	if version != "12 (bookworm)" {
		t.Errorf("version = %q, want '12 (bookworm)'", version)
	}
}

// ── containsVM ────────────────────────────────────────────────────────────────

func TestContainsVM(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"virtualbox", true},
		{"vmware workstation", true},
		{"qemu", true},
		{"kvm guest", true},
		{"virtual machine", true},
		{"macbook pro", false},
		{"thinkpad x1 carbon", false},
		{"", false},
		// containsVM expects pre-lowercased input from callers
		{"VirtualBox", false}, // uppercase is NOT lowercased inside containsVM
	}
	for _, c := range cases {
		if got := containsVM(c.s); got != c.want {
			t.Errorf("containsVM(%q) = %v, want %v", c.s, got, c.want)
		}
	}
}

// ── parseLinuxChassisType ─────────────────────────────────────────────────────

func TestParseLinuxChassisType(t *testing.T) {
	// Codes follow the Linux DMI spec (/sys/class/dmi/id/chassis_type), NOT the
	// Windows WMI ChassisTypes mapping (which differs for codes 15, 16, 21, etc.).
	cases := []struct {
		typeCode, productName, want string
	}{
		// Desktop: codes 3–7
		{"3", "Generic Desktop", "Desktop"},
		{"4", "Low Profile Desktop", "Desktop"},
		{"5", "Pizza Box", "Desktop"},
		{"6", "Mini Tower", "Desktop"},
		{"7", "Tower", "Desktop"},
		// Notebook: codes 8–14
		{"8", "Portable", "Notebook"},
		{"9", "Laptop", "Notebook"},
		{"10", "Notebook", "Notebook"},
		{"14", "Sub Notebook", "Notebook"},
		// Server
		{"17", "PowerEdge R740", "Server"},
		{"23", "Rack Mount Chassis", "Server"},
		{"28", "Blade", "Server"},
		{"29", "Blade Enclosure", "Server"},
		// Tablet: codes 30–32
		{"30", "Tablet", "Tablet"},
		{"31", "Convertible", "Tablet"},
		{"32", "Detachable", "Tablet"},
		// Unrecognised — codes outside mapped ranges return ""
		{"invalid", "anything", ""},
		{"0", "anything", ""},
		{"1", "anything", ""},
		{"15", "Space Saving", ""}, // Windows Desktop but not in Linux mapping
		{"16", "Lunch Box", ""},    // Windows Desktop but not in Linux mapping
		{"21", "Peripheral", ""},   // Windows Notebook but not in Linux mapping
		{"99", "anything", ""},
	}
	for _, c := range cases {
		got := parseLinuxChassisType(c.typeCode, c.productName)
		if got != c.want {
			t.Errorf("parseLinuxChassisType(%q, %q) = %q, want %q",
				c.typeCode, c.productName, got, c.want)
		}
	}
}

func TestParseLinuxChassisType_VMOverridesDesktop(t *testing.T) {
	// Desktop chassis codes (3-7) but product name is a VM hypervisor
	vmProducts := []string{
		"vmware virtual platform",
		"virtualbox",
		"qemu standard pc",
		"kvm virtual machine",
		"virtual machine",
	}
	for _, product := range vmProducts {
		if got := parseLinuxChassisType("3", product); got != "VM" {
			t.Errorf("parseLinuxChassisType(3, %q) = %q, want 'VM'", product, got)
		}
	}
}

func TestParseLinuxChassisType_NotebookIgnoresVM(t *testing.T) {
	// VM keyword in product name does NOT override non-Desktop chassis types
	if got := parseLinuxChassisType("9", "vmware notebook"); got != "Notebook" {
		t.Errorf("Notebook chassis should not be overridden by VM keyword, got %q", got)
	}
}

// ── parseDarwinChassisType ────────────────────────────────────────────────────

func TestParseDarwinChassisType(t *testing.T) {
	cases := []struct{ model, want string }{
		{"MacBook Pro (14-inch, 2021)", "Notebook"},
		{"MacBook Air (M2, 2022)", "Notebook"},
		{"MacBook (12-inch)", "Notebook"},
		{"iMac (24-inch, 2021)", "Desktop"},
		{"Mac mini (M1, 2020)", "Desktop"},
		{"Mac Pro (2023)", "Desktop"},
		{"Mac Studio (2022)", "Desktop"},
		{"Apple Silicon Reference Board", "Other"},
		{"", "Other"},
	}
	for _, c := range cases {
		if got := parseDarwinChassisType(c.model); got != c.want {
			t.Errorf("parseDarwinChassisType(%q) = %q, want %q", c.model, got, c.want)
		}
	}
}

// ── parseDarwinHardwareModel ──────────────────────────────────────────────────

const darwinSPHardwareModelName = `{
  "SPHardwareDataType": [{
    "model_name": "MacBook Pro (14-inch, 2021)",
    "cpu_type": "Apple M1 Pro",
    "serial_number": "C02XXXXX"
  }]
}`

const darwinSPHardwareMachineName = `{
  "SPHardwareDataType": [{
    "machine_name": "Mac mini",
    "cpu_type": "Intel Core i7",
    "serial_number": "C03XXXXX"
  }]
}`

func TestParseDarwinHardwareModel(t *testing.T) {
	got := parseDarwinHardwareModel(darwinSPHardwareModelName)
	if got != "MacBook Pro (14-inch, 2021)" {
		t.Errorf("got %q, want 'MacBook Pro (14-inch, 2021)'", got)
	}
}

func TestParseDarwinHardwareModel_MachineName(t *testing.T) {
	// Older macOS uses machine_name instead of model_name
	got := parseDarwinHardwareModel(darwinSPHardwareMachineName)
	if got != "Mac mini" {
		t.Errorf("got %q, want 'Mac mini'", got)
	}
}

func TestParseDarwinHardwareModel_Invalid(t *testing.T) {
	if got := parseDarwinHardwareModel("not json"); got != "" {
		t.Errorf("expected empty for invalid JSON, got %q", got)
	}
}

func TestParseDarwinHardwareModel_MissingKey(t *testing.T) {
	if got := parseDarwinHardwareModel("{}"); got != "" {
		t.Errorf("expected empty when SPHardwareDataType key is absent, got %q", got)
	}
}

func TestParseDarwinHardwareModel_EmptyArray(t *testing.T) {
	if got := parseDarwinHardwareModel(`{"SPHardwareDataType": []}`); got != "" {
		t.Errorf("expected empty for empty array, got %q", got)
	}
}

// ── integration ───────────────────────────────────────────────────────────────

func TestGetOSInformation_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live OS information collection (shells out to OS commands) in -short mode")
	}

	info := GetOSInformation()
	t.Logf("OSType=%q OSName=%q OSVersion=%q OSServicePack=%q OSPlatform=%q Architecture=%q",
		info.OSType, info.OSName, info.OSVersion, info.OSServicePack, info.OSPlatform, info.Architecture)
	t.Logf("OSLocale=%q OSLanguage=%q OSTimeZone=%q OSTimeZoneOffsetMinutes=%d",
		info.OSLocale, info.OSLanguage, info.OSTimeZone, info.OSTimeZoneOffsetMinutes)

	if info.OSType == "" {
		t.Error("OSType is empty")
	}
	if info.OSName == "" {
		t.Error("OSName is empty")
	}
	if info.Architecture == "" {
		t.Error("Architecture is empty")
	}
	if info.OSPlatform == "" {
		t.Error("OSPlatform is empty")
	}
	if info.OSTimeZone == "" {
		t.Error("OSTimeZone is empty")
	}
}

func TestGetOSInformation_PlatformMatchesRuntime(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	info := GetOSInformation()
	if info.OSPlatform != runtime.GOOS {
		t.Errorf("OSPlatform = %q, want %q (runtime.GOOS)", info.OSPlatform, runtime.GOOS)
	}
}

func TestGetHardwareModel_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping in -short mode")
	}
	model := GetHardwareModel()
	if model == "" {
		t.Error("GetHardwareModel() returned empty string")
	}
	t.Logf("HardwareModel: %q", model)
}
