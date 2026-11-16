package updater

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"sentinelgo/internal/config"
)

func TestDecideUpdate(t *testing.T) {
	cases := []struct {
		name               string
		candidate, current string
		allow              bool
		want               updateAction
		wantErr            bool
	}{
		{"newer", "v2.1.6", "v2.1.5", false, actionUpgrade, false},
		{"newer with the flag", "v2.1.6", "v2.1.5", true, actionUpgrade, false},
		{"older without the flag", "v2.1.4", "v2.1.5", false, actionNone, false},
		{"older with the flag", "v2.1.4", "v2.1.5", true, actionDowngrade, false},
		{"equal", "v2.1.5", "v2.1.5", false, actionNone, false},
		{"equal with the flag", "v2.1.5", "v2.1.5", true, actionNone, false},
		{"dev build with the flag", "v2.1.4", "dev", true, actionNone, true},
	}
	for _, tc := range cases {
		got, err := decideUpdate(tc.candidate, tc.current, tc.allow)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("%s: decideUpdate(%q, %q, %v) = %v, %v; want %v (err %v)",
				tc.name, tc.candidate, tc.current, tc.allow, got, err, tc.want, tc.wantErr)
		}
	}
}

// A release row from an older server has no allow_downgrade column.
func TestLatestRelease_MissingAllowDowngradeIsFalse(t *testing.T) {
	var rows []LatestRelease
	if err := json.Unmarshal([]byte(`[{"version":"v1.0.0","sha256":"ab"}]`), &rows); err != nil {
		t.Fatal(err)
	}
	if rows[0].AllowDowngrade {
		t.Error("AllowDowngrade = true for a row without the field")
	}
	if err := json.Unmarshal([]byte(`[{"version":"v1.0.0","allow_downgrade":true}]`), &rows); err != nil || !rows[0].AllowDowngrade {
		t.Errorf("allow_downgrade not decoded: %+v, %v", rows, err)
	}
}

// End to end: the running agent (v100.0.0) is newer than the server's latest
// release (v99.9.9).
func TestCheckAndApply_Downgrade(t *testing.T) {
	cases := []struct {
		name        string
		running     string
		allow       bool
		badSig      bool
		wantRestart bool
		wantErr     string
	}{
		{"older without the flag is a no-op", "v100.0.0", false, false, false, ""},
		{"older with the flag rolls back", "v100.0.0", true, false, true, ""},
		{"equal with the flag is a no-op", "v99.9.9", true, false, false, ""},
		{"older with the flag but a bad signature is refused", "v100.0.0", true, true, false, "download and verify failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, cfg := newUpdateFixture(t, "")
			config.Version = tc.running
			f.release.AllowDowngrade = tc.allow
			if tc.badSig {
				wrongKey, _ := newTestKeypair(t)
				PublicKey = wrongKey
			}

			err := CheckAndApply(t.Context(), cfg)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("CheckAndApply() error: %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("CheckAndApply() error = %v, want %q", err, tc.wantErr)
			}
			if got := len(f.restarted) == 1; got != tc.wantRestart {
				t.Fatalf("restarted = %v, want restart %v", f.restarted, tc.wantRestart)
			}
			assertNotExist(t, f.self+".backup", "backup")
			if !tc.wantRestart {
				if got := mustReadFile(t, f.self); !bytes.Equal(got, f.oldBinary) {
					t.Errorf("self must be untouched, got %q", got)
				}
				return
			}
			installed := f.self
			if runtime.GOOS == "windows" {
				installed = f.self + ".new" // swapped in by the restart script
			}
			if got := mustReadFile(t, installed); !bytes.Equal(got, f.newBinary) {
				t.Errorf("installed = %q, want the rollback release %q", got, f.newBinary)
			}
		})
	}
}
