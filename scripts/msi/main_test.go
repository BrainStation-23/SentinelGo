package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestMSIVersion(t *testing.T) {
	for tag, want := range map[string]string{"v4.0.8": "4.0.8", "v255.255.65535": "255.255.65535", "v10.0.0": "10.0.0"} {
		if got, err := msiVersion(tag); err != nil || got != want {
			t.Errorf("%s: %q %v", tag, got, err)
		}
	}
	for _, tag := range []string{"4.0.8", "v4.0", "v4.0.8-rc1", "v256.0.0", "v1.256.0", "v1.0.65536", ""} {
		if _, err := msiVersion(tag); err == nil {
			t.Errorf("%s accepted", tag)
		}
	}
}

func TestProductCode(t *testing.T) {
	guid := regexp.MustCompile(`^\{[0-9A-F]{8}-[0-9A-F]{4}-5[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}\}$`)
	a, b := productCode("4.0.8"), productCode("4.0.9")
	if !guid.MatchString(a) || !guid.MatchString(b) {
		t.Fatalf("not a v5 GUID: %s %s", a, b)
	}
	if a == b || a == UpgradeCode {
		t.Errorf("product codes %s %s", a, b)
	}
	// Stable: a rebuild of a version gets the same code. Changing this value
	// breaks the backend's install commands for every published version.
	// (Python agrees: uuid.uuid5(UUID(UpgradeCode), "4.0.8").)
	if a != "{BE398A49-6E0B-55F0-A94D-5D683AA9E021}" {
		t.Errorf("4.0.8's ProductCode changed: %s", a)
	}
}

func TestRun(t *testing.T) {
	var out bytes.Buffer
	if err := run([]string{"-version", "v4.1.0", "-vars"}, &out); err != nil {
		t.Fatal(err)
	}
	want := "MSI_VERSION=4.1.0\nPRODUCT_CODE=" + productCode("4.1.0") + "\nUPGRADE_CODE=" + UpgradeCode + "\n"
	if out.String() != want {
		t.Errorf("vars:\n%s", out.String())
	}

	dir := t.TempDir()
	msi := filepath.Join(dir, MSIName)
	if err := os.WriteFile(msi, []byte("msi"), 0o600); err != nil {
		t.Fatal(err)
	}
	js := filepath.Join(dir, "sentinelgo-installers.json")
	if err := run([]string{"-version", "v4.1.0", "-manifest", js, "-msi", msi}, &out); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(js)
	var got Installers
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != "v4.1.0" || got.MSI.Name != MSIName || got.MSI.ProductCode != productCode("4.1.0") ||
		got.MSI.SHA256 != "7f1d49243ee662770bbdff7da2cec54eb382cd9d76dfa7b049a620ec457db57b" { // sha256("msi")
		t.Errorf("manifest %+v", got)
	}

	for _, args := range [][]string{
		{"-version", "v4.1", "-vars"},
		{"-version", "v4.1.0"},
		{"-version", "v4.1.0", "-manifest", js, "-msi", filepath.Join(dir, "other.msi")},
	} {
		if err := run(args, &out); err == nil {
			t.Errorf("%s: no error", strings.Join(args, " "))
		}
	}
}
