package posture

import (
	"reflect"
	"testing"
)

func TestParseNetAccounts(t *testing.T) {
	const sample = `Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          42
Minimum password length:                               7
Length of password history maintained:                24
Lockout threshold:                                     5
Lockout duration (minutes):                            30
Lockout observation window (minutes):                  30
Computer role:                                         WORKSTATION
`
	got := parseNetAccounts(sample)
	if got.MinLength == nil || *got.MinLength != 7 {
		t.Errorf("MinLength = %v, want 7", got.MinLength)
	}
	if got.MinAgeDays == nil || *got.MinAgeDays != 0 {
		t.Errorf("MinAgeDays = %v, want 0", got.MinAgeDays)
	}
	if got.MaxAgeDays == nil || *got.MaxAgeDays != 42 {
		t.Errorf("MaxAgeDays = %v, want 42", got.MaxAgeDays)
	}
	if got.LockoutThreshold == nil || *got.LockoutThreshold != 5 {
		t.Errorf("LockoutThreshold = %v, want 5", got.LockoutThreshold)
	}
	if got.LockoutDurationMinutes == nil || *got.LockoutDurationMinutes != 30 {
		t.Errorf("LockoutDurationMinutes = %v, want 30", got.LockoutDurationMinutes)
	}
}

func TestParseNetAccounts_NonNumericValuesLeftNil(t *testing.T) {
	const sample = `Maximum password age (days):                          Unlimited
Lockout threshold:                                     Never
`
	got := parseNetAccounts(sample)
	if got.MaxAgeDays != nil {
		t.Errorf("MaxAgeDays = %v, want nil for 'Unlimited' (not fabricated as 0)", *got.MaxAgeDays)
	}
	if got.LockoutThreshold != nil {
		t.Errorf("LockoutThreshold = %v, want nil for 'Never'", *got.LockoutThreshold)
	}
}

func TestParseNetLocalgroupMembers(t *testing.T) {
	const sample = `Alias name     Administrators
Comment        Administrators have complete and unrestricted access

Members

-------------------------------------------------------------------------
Administrator
jdoe
The command completed successfully.

`
	got := parseNetLocalgroupMembers(sample)
	want := []string{"Administrator", "jdoe"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseNetLocalgroupMembers_NoSeparator(t *testing.T) {
	if got := parseNetLocalgroupMembers("unexpected output with no dashed line"); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestParseLoginDefs(t *testing.T) {
	const sample = `# comment line
PASS_MAX_DAYS   90
PASS_MIN_DAYS   7
PASS_MIN_LEN    8
UID_MIN                  1000
`
	got := parseLoginDefs(sample)
	if got.MaxAgeDays == nil || *got.MaxAgeDays != 90 {
		t.Errorf("MaxAgeDays = %v, want 90", got.MaxAgeDays)
	}
	if got.MinAgeDays == nil || *got.MinAgeDays != 7 {
		t.Errorf("MinAgeDays = %v, want 7", got.MinAgeDays)
	}
	if got.MinLength == nil || *got.MinLength != 8 {
		t.Errorf("MinLength = %v, want 8", got.MinLength)
	}
}

func TestParseFaillockConf(t *testing.T) {
	const sample = `# comment
audit
silent
deny = 5
unlock_time = 900
`
	got := parseFaillockConf(sample)
	if got == nil || *got != 5 {
		t.Errorf("got %v, want 5", got)
	}
}

func TestParseFaillockConf_Absent(t *testing.T) {
	if got := parseFaillockConf("audit\nsilent\n"); got != nil {
		t.Errorf("got %v, want nil", *got)
	}
}

func TestParseEtcGroupMembers(t *testing.T) {
	const sample = `root:x:0:
sudo:x:27:jdoe,asmith
wheel:x:10:
docker:x:999:jdoe
`
	got := parseEtcGroupMembers(sample, "sudo")
	want := []string{"jdoe", "asmith"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	if got := parseEtcGroupMembers(sample, "wheel"); got != nil {
		t.Errorf("wheel (empty member list) = %v, want nil", got)
	}

	if got := parseEtcGroupMembers(sample, "nonexistent"); got != nil {
		t.Errorf("nonexistent group = %v, want nil", got)
	}
}

func TestParseDsclGroupMembership(t *testing.T) {
	const sample = "GroupMembership: root jdoe asmith\n"
	got := parseDsclGroupMembership(sample)
	want := []string{"root", "jdoe", "asmith"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseDsclGroupMembership_Empty(t *testing.T) {
	if got := parseDsclGroupMembership("GroupMembership: \n"); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}
