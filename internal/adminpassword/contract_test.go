package adminpassword

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestGenerate_LengthAndClasses(t *testing.T) {
	for complexity := 1; complexity <= 4; complexity++ {
		for _, length := range []int{MinLength, DefaultLength, MaxLength} {
			for i := 0; i < 50; i++ {
				pw, err := Generate(length, complexity)
				if err != nil {
					t.Fatal(err)
				}
				if len(pw) != length {
					t.Fatalf("length %d, want %d", len(pw), length)
				}
				for c := 0; c < 4; c++ {
					has := bytes.ContainsAny(pw, classes[c])
					if c < complexity && !has {
						t.Fatalf("complexity %d: missing class %d in a password", complexity, c)
					}
					if c >= complexity && has {
						t.Fatalf("complexity %d: class %d not allowed", complexity, c)
					}
				}
				for _, b := range pw {
					if b < 0x21 || b > 0x7e || b == '"' || b == '\'' || b == '\\' || b == '`' {
						t.Fatalf("unexpected character %q", b)
					}
				}
			}
		}
	}
}

func TestGenerate_NotRepeated(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		pw, err := Generate(DefaultLength, 4)
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(pw)] {
			t.Fatal("generated the same password twice")
		}
		seen[string(pw)] = true
	}
}

func TestGenerate_Rejects(t *testing.T) {
	for _, c := range [][2]int{{24, 0}, {24, 5}, {3, 4}, {MaxLength + 1, 4}} {
		if _, err := Generate(c[0], c[1]); err == nil {
			t.Errorf("Generate(%d, %d) succeeded", c[0], c[1])
		}
	}
}

func TestZero(t *testing.T) {
	b := []byte("secret")
	zero(b)
	if !bytes.Equal(b, make([]byte, 6)) {
		t.Fatalf("not zeroed: %v", b)
	}
}

func TestDecodePolicyResponse(t *testing.T) {
	raw := `{"changed":true,"policy":{"version":"v1","enabled":true,"account":{"name":"LocalAdm"},
	  "password":{"length":32,"complexity":3},"rotate_every_days":7,"post_use_delay_hours":0},
	  "rotate_after":"2026-11-12T09:30:00Z"}`
	got, err := DecodePolicyResponse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	p := got.Policy
	if !got.Changed || p.Version != "v1" || !p.Enabled || p.Account.Name != "LocalAdm" ||
		p.Password.Length != 32 || p.Password.Complexity != 3 || p.RotateEveryDays != 7 || p.PostUseDelay() != 0 {
		t.Fatalf("decoded %+v", got)
	}
	if got.RotateAfter == nil || !got.RotateAfter.Equal(time.Date(2026, 11, 12, 9, 30, 0, 0, time.UTC)) {
		t.Fatalf("rotate_after = %v", got.RotateAfter)
	}
}

func TestDecodePolicyResponse_Unchanged(t *testing.T) {
	got, err := DecodePolicyResponse([]byte(`{"changed":false,"rotate_after":null}`))
	if err != nil || got.Changed || got.RotateAfter != nil {
		t.Fatalf("got %+v, %v", got, err)
	}
	// rotate_after comes with an unchanged policy too.
	got, err = DecodePolicyResponse([]byte(`{"changed":false,"rotate_after":"2026-11-12T09:30:00Z"}`))
	if err != nil || got.RotateAfter == nil {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestDecodePolicyResponse_ClampsToDefaults(t *testing.T) {
	raw := `{"changed":true,"policy":{"version":"v","enabled":true,"account":{"name":""},
	  "password":{"length":8,"complexity":9},"rotate_every_days":0,"post_use_delay_hours":-1}}`
	got, err := DecodePolicyResponse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	p := got.Policy
	if p.Password.Length != DefaultLength || p.Password.Complexity != DefaultComplexity ||
		p.RotateEveryDays != DefaultRotateDays || p.PostUseDelay() != DefaultPostUseHours*time.Hour {
		t.Fatalf("not clamped: %+v", p)
	}
	// A missing post-use delay is the default, not 0.
	got, err = DecodePolicyResponse([]byte(`{"changed":true,"policy":{"version":"v","enabled":true}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got.Policy.PostUseDelay() != DefaultPostUseHours*time.Hour {
		t.Fatalf("post-use delay = %v", got.Policy.PostUseDelay())
	}
}

func TestDecodePolicyResponse_Rejects(t *testing.T) {
	long := strings.Repeat("x", maxResponseBytes)
	for name, raw := range map[string]string{
		"not json":         `{`,
		"no policy":        `{"changed":true}`,
		"null policy":      `{"changed":true,"policy":null}`,
		"no version":       `{"changed":true,"policy":{"enabled":true}}`,
		"bad account":      `{"changed":true,"policy":{"version":"v","account":{"name":"..\\evil"}}}`,
		"account too long": `{"changed":true,"policy":{"version":"v","account":{"name":"abcdefghijklmnopqrstu"}}}`,
		"domain account":   `{"changed":true,"policy":{"version":"v","account":{"name":"CONTOSO\\admin"}}}`,
		"bad rotate_after": `{"changed":false,"rotate_after":"tomorrow"}`,
		"oversized":        `{"changed":false,"pad":"` + long + `"}`,
	} {
		if _, err := DecodePolicyResponse([]byte(raw)); !errors.Is(err, ErrBadPolicy) {
			t.Errorf("%s: err = %v, want ErrBadPolicy", name, err)
		}
	}
}

func TestStatusEncode(t *testing.T) {
	by := ManagedByWindowsLAPS
	s := Status{SchemaVersion: 1, State: StateManagedElsewhere, ManagedBy: &by}
	data, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schema_version", "state", "managed_by", "account", "last_rotated_at", "next_rotation_at", "pending_rotation_id", "last_error"} {
		if _, ok := m[k]; !ok {
			t.Errorf("status lacks %q: %s", k, data)
		}
	}
	big := Status{PolicyVersion: strings.Repeat("v", MaxStatusBytes)}
	if _, err := big.Encode(); err == nil {
		t.Error("oversized status encoded")
	}
}

func TestEscrow_FormatHidesPassword(t *testing.T) {
	e := Escrow{RotationID: "id", AccountName: "Administrator", Password: "Hunter2-Hunter2!"}
	for _, s := range []string{fmt.Sprint(e), fmt.Sprintf("%v", e), fmt.Sprintf("%+v", e), fmt.Sprintf("%#v", e), e.String()} {
		if strings.Contains(s, e.Password) {
			t.Fatalf("formatted escrow shows the password: %s", s)
		}
	}
}

func TestNewRotationID(t *testing.T) {
	id, err := newRotationID()
	if err != nil {
		t.Fatal(err)
	}
	if len(id) != 36 || id[14] != '4' || strings.Count(id, "-") != 4 {
		t.Fatalf("not a v4 UUID: %s", id)
	}
}

func TestManagedByFrom(t *testing.T) {
	type val struct {
		v     uint32
		found bool
	}
	cases := []struct {
		name string
		keys map[string]map[string]val
		want string
	}{
		{"nothing", nil, ""},
		{"CSP to Entra", map[string]map[string]val{windowsLAPSRoots[0]: {"BackupDirectory": {1, true}}}, ManagedByWindowsLAPS},
		{"GPO to AD", map[string]map[string]val{windowsLAPSRoots[1]: {"BackupDirectory": {2, true}}}, ManagedByWindowsLAPS},
		{"local config", map[string]map[string]val{windowsLAPSRoots[2]: {"BackupDirectory": {1, true}}}, ManagedByWindowsLAPS},
		{"CSP disabled wins over GPO", map[string]map[string]val{
			windowsLAPSRoots[0]: {"BackupDirectory": {0, true}},
			windowsLAPSRoots[1]: {"BackupDirectory": {2, true}},
		}, ""},
		{"CSP key without the value", map[string]map[string]val{windowsLAPSRoots[0]: {}}, ""},
		{"legacy LAPS", map[string]map[string]val{legacyLAPSKey: {"AdmPwdEnabled": {1, true}}}, ManagedByLegacyLAPS},
		{"legacy LAPS off", map[string]map[string]val{legacyLAPSKey: {"AdmPwdEnabled": {0, true}}}, ""},
	}
	for _, c := range cases {
		read := func(key, value string) (uint32, bool, bool, error) {
			k, ok := c.keys[key]
			if !ok {
				return 0, false, false, nil
			}
			v := k[value]
			return v.v, true, v.found, nil
		}
		got, err := managedByFrom(read)
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.name, got, err, c.want)
		}
	}
	boom := errors.New("access denied")
	if _, err := managedByFrom(func(string, string) (uint32, bool, bool, error) { return 0, false, false, boom }); !errors.Is(err, boom) {
		t.Errorf("read error not returned: %v", err)
	}
}

func FuzzDecodePolicyResponse(f *testing.F) {
	f.Add([]byte(`{"changed":true,"policy":{"version":"v","enabled":true,"account":{"name":"a"},"password":{"length":24,"complexity":4},"rotate_every_days":30,"post_use_delay_hours":8},"rotate_after":null}`))
	f.Add([]byte(`{"changed":false,"rotate_after":"2026-11-12T09:30:00Z"}`))
	f.Add([]byte(`{"changed":true,"policy":{"version":"v","password":{"length":-1}}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, err := DecodePolicyResponse(raw)
		if err != nil || !got.Changed {
			return
		}
		p := got.Policy
		if p.Version == "" || p.Password.Length < MinLength || p.Password.Length > MaxLength ||
			p.Password.Complexity < 1 || p.Password.Complexity > 4 ||
			p.RotateEveryDays < 1 || p.RotateEveryDays > MaxRotateDays ||
			p.PostUseDelay() < 0 || p.PostUseDelay() > MaxPostUseHours*time.Hour {
			t.Fatalf("accepted out-of-range policy %+v", p)
		}
		if p.Account.Name != "" && !accountNameRe.MatchString(p.Account.Name) {
			t.Fatalf("accepted account name %q", p.Account.Name)
		}
		if _, err := Generate(p.Password.Length, p.Password.Complexity); err != nil {
			t.Fatalf("accepted policy can't generate: %v", err)
		}
	})
}
