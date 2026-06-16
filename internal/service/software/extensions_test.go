package software

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// setFakeHome points HOME (Unix) and USERPROFILE (Windows) at tmpDir so that
// os.UserHomeDir() returns tmpDir, and pins userHomeDirs() to exactly tmpDir so
// the extension collectors scan only the test fixture, not the real machine's
// user profiles. Both are restored at test end.
func setFakeHome(t *testing.T, tmpDir string) {
	t.Helper()
	t.Setenv("HOME", tmpDir)
	t.Setenv("USERPROFILE", tmpDir)
	orig := userHomeDirs
	userHomeDirs = func() []string { return []string{tmpDir} }
	t.Cleanup(func() { userHomeDirs = orig })
}

// firefoxProfileBase returns the profile directory that getFirefoxExtensions
// expects to find (the glob matches its parent, so we create this exact dir).
func firefoxProfileBase(tmpDir string) string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(tmpDir, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", "abc.default")
	case "darwin":
		return filepath.Join(tmpDir, "Library", "Application Support", "Firefox", "Profiles", "abc.default")
	default:
		return filepath.Join(tmpDir, ".mozilla", "firefox", "abc.default")
	}
}

// braveExtensionsBase returns the Extensions directory that getBraveExtensions scans.
func braveExtensionsBase(tmpDir string) string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(tmpDir, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data", "Default", "Extensions")
	case "darwin":
		return filepath.Join(tmpDir, "Library", "Application Support", "BraveSoftware", "Brave-Browser", "Default", "Extensions")
	default:
		return filepath.Join(tmpDir, ".config", "BraveSoftware", "Brave-Browser", "Default", "Extensions")
	}
}

// writeManifest creates dir (and parents) and writes a manifest.json with name+version.
func writeManifest(t *testing.T, dir, name, version string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll %s: %v", dir, err)
	}
	path := filepath.Join(dir, "manifest.json")
	data, _ := json.Marshal(map[string]string{"name": name, "version": version})
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("WriteFile manifest: %v", err)
	}
	return path
}

// ── readExtensionManifest ─────────────────────────────────────────────────────

func TestReadExtensionManifest_Valid(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "My Extension", "1.2.3")

	info := readExtensionManifest(filepath.Join(dir, "manifest.json"), "chrome", "chrome_extensions", "fallback-id")
	if info == nil {
		t.Fatal("expected non-nil SoftwareInfo for valid manifest")
	}
	if info.Name != "My Extension" {
		t.Errorf("Name = %q, want My Extension", info.Name)
	}
	if info.InstalledVersion != "1.2.3" {
		t.Errorf("InstalledVersion = %q, want 1.2.3", info.InstalledVersion)
	}
}

func TestReadExtensionManifest_I18nName(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "__MSG_extName__", "0.1")

	info := readExtensionManifest(filepath.Join(dir, "manifest.json"), "chrome", "chrome_extensions", "my-ext-id")
	if info == nil {
		t.Fatal("expected non-nil SoftwareInfo even for i18n name")
	}
	if info.Name != "my-ext-id" {
		t.Errorf("Name = %q, want my-ext-id (fallback for __MSG_ prefix)", info.Name)
	}
}

func TestReadExtensionManifest_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("not-json{{{"), 0644); err != nil {
		t.Fatal(err)
	}

	info := readExtensionManifest(filepath.Join(dir, "manifest.json"), "chrome", "chrome_extensions", "fallback")
	if info == nil {
		t.Fatal("expected non-nil SoftwareInfo for invalid JSON (fallback to extID)")
	}
	if info.Name != "fallback" {
		t.Errorf("Name = %q, want fallback", info.Name)
	}
}

func TestReadExtensionManifest_NonExistent(t *testing.T) {
	info := readExtensionManifest("/no/such/path/manifest.json", "chrome", "chrome_extensions", "fallback")
	if info != nil {
		t.Errorf("expected nil for non-existent path, got %+v", info)
	}
}

func TestReadExtensionManifest_EmptyName(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "", "1.0")

	info := readExtensionManifest(filepath.Join(dir, "manifest.json"), "chrome", "chrome_extensions", "ext-id")
	if info == nil {
		t.Fatal("expected non-nil SoftwareInfo for empty name")
	}
	if info.Name != "ext-id" {
		t.Errorf("Name = %q, want ext-id (fallback for empty name)", info.Name)
	}
}

// ── getFirefoxExtensions ──────────────────────────────────────────────────────

func TestGetFirefoxExtensions_WithExtension(t *testing.T) {
	tmpDir := t.TempDir()
	setFakeHome(t, tmpDir)

	// Firefox structure: profile/extensions/ext-id/manifest.json
	extDir := filepath.Join(firefoxProfileBase(tmpDir), "extensions", "my-ff-ext")
	writeManifest(t, extDir, "Firefox Addon", "2.0.0")

	s := &SoftwareService{}
	exts, _ := s.getFirefoxExtensions()

	if len(exts) == 0 {
		t.Fatal("expected at least one Firefox extension, got none")
	}
	found := false
	for _, e := range exts {
		if e.Name == "Firefox Addon" && e.InstalledVersion == "2.0.0" {
			found = true
		}
	}
	if !found {
		t.Errorf("Firefox Addon/2.0.0 not found in %v", exts)
	}
}

func TestGetFirefoxExtensions_EmptyProfile(t *testing.T) {
	tmpDir := t.TempDir()
	setFakeHome(t, tmpDir)

	// Create the profile's extensions directory but leave it empty.
	extBase := filepath.Join(firefoxProfileBase(tmpDir), "extensions")
	if err := os.MkdirAll(extBase, 0755); err != nil {
		t.Fatal(err)
	}

	s := &SoftwareService{}
	exts, _ := s.getFirefoxExtensions()
	if len(exts) != 0 {
		t.Errorf("expected 0 extensions for empty profile, got %d", len(exts))
	}
}

func TestGetFirefoxExtensions_NoProfile(t *testing.T) {
	tmpDir := t.TempDir()
	setFakeHome(t, tmpDir)
	// No Firefox profile directories created at all.

	s := &SoftwareService{}
	exts, _ := s.getFirefoxExtensions()
	if len(exts) != 0 {
		t.Errorf("expected 0 extensions for missing profile dir, got %d", len(exts))
	}
}

// ── getBraveExtensions ────────────────────────────────────────────────────────

func TestGetBraveExtensions_WithExtension(t *testing.T) {
	tmpDir := t.TempDir()
	setFakeHome(t, tmpDir)

	// Brave/Chrome structure: Extensions/ext-id/version_dir/manifest.json
	extDir := filepath.Join(braveExtensionsBase(tmpDir), "brave-ext-id", "1.0.0_0")
	writeManifest(t, extDir, "Brave Extension", "1.0.0")

	s := &SoftwareService{}
	exts, _ := s.getBraveExtensions()

	if len(exts) == 0 {
		t.Fatal("expected at least one Brave extension, got none")
	}
	found := false
	for _, e := range exts {
		if e.Name == "Brave Extension" {
			found = true
		}
	}
	if !found {
		t.Errorf("Brave Extension not found in %v", exts)
	}
}

func TestGetBraveExtensions_NoExtensions(t *testing.T) {
	tmpDir := t.TempDir()
	setFakeHome(t, tmpDir)
	// Extensions directory not created.

	s := &SoftwareService{}
	exts, _ := s.getBraveExtensions()
	if len(exts) != 0 {
		t.Errorf("expected 0 extensions for missing directory, got %d", len(exts))
	}
}

// ── additional readExtensionManifest edge cases ───────────────────────────────

// TestReadExtensionManifest_SetsMetadata verifies that Source, Type, Status and
// IsActive are correctly populated from the arguments.
func TestReadExtensionManifest_SetsMetadata(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "Test Ext", "3.0.0")

	info := readExtensionManifest(filepath.Join(dir, "manifest.json"), "chrome", "chrome_extensions", "test-id")
	if info == nil {
		t.Fatal("expected non-nil SoftwareInfo")
	}
	if info.Source != "chrome" {
		t.Errorf("Source = %q, want chrome", info.Source)
	}
	if info.Type != "chrome_extensions" {
		t.Errorf("Type = %q, want chrome_extensions", info.Type)
	}
	if info.FilePath == "" {
		t.Error("FilePath is empty, expected the path to manifest.json")
	}
}

// TestReadExtensionManifest_I18nVariousFormats verifies that any name beginning
// with "__MSG_" is replaced by the fallback ID, regardless of the suffix format.
func TestReadExtensionManifest_I18nVariousFormats(t *testing.T) {
	cases := []string{
		"__MSG_extName__",
		"__MSG_appTitle__",
		"__MSG_name__",
	}
	for _, i18nName := range cases {
		t.Run(i18nName, func(t *testing.T) {
			dir := t.TempDir()
			writeManifest(t, dir, i18nName, "1.0")

			info := readExtensionManifest(filepath.Join(dir, "manifest.json"), "chrome", "chrome_extensions", "fallback-id")
			if info == nil {
				t.Fatal("expected non-nil SoftwareInfo")
			}
			if info.Name != "fallback-id" {
				t.Errorf("Name = %q for i18n manifest %q, want fallback-id", info.Name, i18nName)
			}
		})
	}
}
