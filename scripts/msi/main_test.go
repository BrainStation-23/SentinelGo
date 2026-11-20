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
	a, b := productCode("4.0.8", FlavorFull), productCode("4.0.9", FlavorFull)
	ra, rb := productCode("4.0.8", FlavorReadOnly), productCode("4.0.9", FlavorReadOnly)
	for _, c := range []string{a, b, ra, rb} {
		if !guid.MatchString(c) {
			t.Fatalf("not a v5 GUID: %s", c)
		}
	}
	seen := map[string]bool{UpgradeCode: true}
	for _, c := range []string{a, b, ra, rb} {
		if seen[c] {
			t.Errorf("product code %s repeats", c)
		}
		seen[c] = true
	}
	// Stable: a rebuild of a version gets the same code. Changing these
	// values breaks the backend's install commands for every published
	// version. (Python agrees: uuid.uuid5(UUID(UpgradeCode), "4.0.8") and
	// uuid.uuid5(UUID(UpgradeCode), "4.0.8/readonly").)
	if a != "{BE398A49-6E0B-55F0-A94D-5D683AA9E021}" {
		t.Errorf("4.0.8's ProductCode changed: %s", a)
	}
	if ra != "{826AAE93-9AC8-5817-9834-7079E370535E}" {
		t.Errorf("4.0.8 read-only's ProductCode changed: %s", ra)
	}
}

func TestNames(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{msiName(FlavorFull), "sentinelgo-windows-amd64.msi"},
		{msiName(FlavorReadOnly), "sentinelgo-readonly-windows-amd64.msi"},
		{pkgName(FlavorFull), "sentinelgo-darwin-universal.pkg"},
		{pkgName(FlavorReadOnly), "sentinelgo-readonly-darwin-universal.pkg"},
		{productName(FlavorFull), "SentinelGo Agent"},
		{productName(FlavorReadOnly), "SentinelGo Agent (readonly)"},
	} {
		if c.got != c.want {
			t.Errorf("got %s, want %s", c.got, c.want)
		}
	}
}

func TestVars(t *testing.T) {
	for _, f := range flavors {
		var out bytes.Buffer
		if err := run([]string{"-version", "v4.1.0", "-flavor", f, "-vars"}, &out); err != nil {
			t.Fatal(err)
		}
		want := "MSI_VERSION=4.1.0\nPRODUCT_CODE=" + productCode("4.1.0", f) + "\nUPGRADE_CODE=" + UpgradeCode +
			"\nPRODUCT_NAME=" + productName(f) + "\n"
		if out.String() != want {
			t.Errorf("%s vars:\n%s", f, out.String())
		}
	}
	// Without -flavor: the full build.
	var out bytes.Buffer
	if err := run([]string{"-version", "v4.1.0", "-vars"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "PRODUCT_CODE="+productCode("4.1.0", FlavorFull)+"\n") {
		t.Errorf("default vars:\n%s", out.String())
	}
}

// writeAsset writes content to dir/name and returns the path.
func writeAsset(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func readManifest(t *testing.T, path string) (Installers, map[string]any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got Installers
	var raw map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	return got, raw
}

const (
	sumMSI   = "7f1d49243ee662770bbdff7da2cec54eb382cd9d76dfa7b049a620ec457db57b" // sha256("msi")
	sumPkg   = "e0ce1a7f3f76d7bfda0ffdae6e0226aa63b3009c4c4a770c321876aecad0a6c1" // sha256("pkg")
	sumROMSI = "a3dcafeadf6e3222b5004df068b63a60d25cca3ab22c5a6cd7dad5497d5a1eca" // sha256("ro-msi")
	sumROPkg = "d9341a8b356423e9b3d4dc8a686d689e86b2e4d69ed8cde740a4b474e87d7b9f" // sha256("ro-pkg")
)

func TestManifestFullOnly(t *testing.T) {
	dir := t.TempDir()
	msi := writeAsset(t, dir, msiName(FlavorFull), "msi")
	js := filepath.Join(dir, "sentinelgo-installers.json")
	var out bytes.Buffer
	if err := run([]string{"-version", "v4.1.0", "-manifest", js, "-msi", msi}, &out); err != nil {
		t.Fatal(err)
	}
	got, raw := readManifest(t, js)
	want := InstallerInfo{Name: "sentinelgo-windows-amd64.msi", ProductCode: productCode("4.1.0", FlavorFull), SHA256: sumMSI}
	if got.Version != "v4.1.0" || got.MSI != want {
		t.Errorf("manifest %+v", got)
	}
	if _, ok := raw["pkg"]; ok {
		t.Errorf("without -pkg the key must be absent: %v", raw)
	}
	if len(got.Flavors) != 1 || got.Flavors[FlavorFull].MSI == nil || *got.Flavors[FlavorFull].MSI != want ||
		got.Flavors[FlavorFull].Pkg != nil {
		t.Errorf("flavors %+v", got.Flavors)
	}
}

func TestManifestBothFlavors(t *testing.T) {
	dir := t.TempDir()
	js := filepath.Join(dir, "sentinelgo-installers.json")
	args := []string{"-version", "v4.1.0", "-manifest", js,
		"-msi", writeAsset(t, dir, msiName(FlavorFull), "msi"),
		"-msi", writeAsset(t, dir, msiName(FlavorReadOnly), "ro-msi"),
		"-pkg", writeAsset(t, dir, pkgName(FlavorFull), "pkg"),
		"-pkg", writeAsset(t, dir, pkgName(FlavorReadOnly), "ro-pkg"),
	}
	var out bytes.Buffer
	if err := run(args, &out); err != nil {
		t.Fatal(err)
	}
	got, _ := readManifest(t, js)

	fullMSI := InstallerInfo{Name: "sentinelgo-windows-amd64.msi", ProductCode: productCode("4.1.0", FlavorFull), SHA256: sumMSI}
	fullPkg := PkgInfo{Name: "sentinelgo-darwin-universal.pkg", Identifier: "com.sentinelgo.agent", SHA256: sumPkg}
	roMSI := InstallerInfo{Name: "sentinelgo-readonly-windows-amd64.msi", ProductCode: productCode("4.1.0", FlavorReadOnly), SHA256: sumROMSI}
	roPkg := PkgInfo{Name: "sentinelgo-readonly-darwin-universal.pkg", Identifier: "com.sentinelgo.agent", SHA256: sumROPkg}

	// The top level stays the full build's, for mirrors that don't know flavors.
	if got.MSI != fullMSI || got.Pkg == nil || *got.Pkg != fullPkg {
		t.Errorf("top level %+v %+v", got.MSI, got.Pkg)
	}
	f, r := got.Flavors[FlavorFull], got.Flavors[FlavorReadOnly]
	if f.MSI == nil || *f.MSI != fullMSI || f.Pkg == nil || *f.Pkg != fullPkg {
		t.Errorf("flavors.full %+v", f)
	}
	if r.MSI == nil || *r.MSI != roMSI || r.Pkg == nil || *r.Pkg != roPkg {
		t.Errorf("flavors.readonly %+v", r)
	}
}

func TestManifestReadOnlyMSIWithoutPkg(t *testing.T) {
	// An unsigned read-only package isn't listed: the flavor has no pkg key.
	dir := t.TempDir()
	js := filepath.Join(dir, "sentinelgo-installers.json")
	var out bytes.Buffer
	if err := run([]string{"-version", "v4.1.0", "-manifest", js,
		"-msi", writeAsset(t, dir, msiName(FlavorFull), "msi"),
		"-msi", writeAsset(t, dir, msiName(FlavorReadOnly), "ro-msi"),
	}, &out); err != nil {
		t.Fatal(err)
	}
	_, raw := readManifest(t, js)
	ro, _ := raw["flavors"].(map[string]any)["readonly"].(map[string]any)
	if _, ok := ro["pkg"]; ok || ro["msi"] == nil {
		t.Errorf("flavors.readonly %v", ro)
	}
}

func TestRunErrors(t *testing.T) {
	dir := t.TempDir()
	msi := writeAsset(t, dir, msiName(FlavorFull), "msi")
	roMSI := writeAsset(t, dir, msiName(FlavorReadOnly), "ro-msi")
	js := filepath.Join(dir, "sentinelgo-installers.json")
	var out bytes.Buffer
	for _, args := range [][]string{
		{"-version", "v4.1", "-vars"},
		{"-version", "v4.1.0", "-flavor", "other", "-vars"},
		{"-version", "v4.1.0", "-manifest", js, "-msi", msi, "-pkg", writeAsset(t, dir, "other.pkg", "pkg")},
		{"-version", "v4.1.0"},
		{"-version", "v4.1.0", "-manifest", js, "-msi", writeAsset(t, dir, "other.msi", "msi")},
		{"-version", "v4.1.0", "-manifest", js, "-msi", writeAsset(t, dir, "sentinelgo-other-windows-amd64.msi", "msi")},
		// The full MSI is required.
		{"-version", "v4.1.0", "-manifest", js, "-msi", roMSI},
		// A flavor given twice.
		{"-version", "v4.1.0", "-manifest", js, "-msi", msi, "-msi", msi},
	} {
		if err := run(args, &out); err == nil {
			t.Errorf("%s: no error", strings.Join(args, " "))
		}
	}
}
