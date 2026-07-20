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
		return // Early return to satisfy staticcheck
	}
	// Name is the stable extension ID; DisplayName is the human-readable label.
	if info.Name != "fallback-id" {
		t.Errorf("Name = %q, want fallback-id (extension ID)", info.Name)
	}
	if info.DisplayName != "My Extension" {
		t.Errorf("DisplayName = %q, want My Extension", info.DisplayName)
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
		return // Early return to satisfy staticcheck
	}
	if info.Name != "my-ext-id" {
		t.Errorf("Name = %q, want my-ext-id (extension ID)", info.Name)
	}
	// Without locale files, DisplayName should fall back to the extension ID.
	if info.DisplayName != "my-ext-id" {
		t.Errorf("DisplayName = %q, want my-ext-id (fallback for unresolved __MSG_)", info.DisplayName)
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
		return // Early return to satisfy staticcheck
	}
	if info.Name != "fallback" {
		t.Errorf("Name = %q, want fallback", info.Name)
	}
	if info.DisplayName != "fallback" {
		t.Errorf("DisplayName = %q, want fallback", info.DisplayName)
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
		return // Early return to satisfy staticcheck
	}
	if info.Name != "ext-id" {
		t.Errorf("Name = %q, want ext-id (extension ID)", info.Name)
	}
	if info.DisplayName != "ext-id" {
		t.Errorf("DisplayName = %q, want ext-id (fallback for empty manifest name)", info.DisplayName)
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
		if e.DisplayName == "Firefox Addon" && e.InstalledVersion == "2.0.0" {
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
		if e.DisplayName == "Brave Extension" {
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
		return // Early return to satisfy staticcheck
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
				return // Early return to satisfy staticcheck
			}
			// Without locale files, Name is the extension ID and DisplayName falls back to it too.
			if info.Name != "fallback-id" {
				t.Errorf("Name = %q for i18n manifest %q, want fallback-id", info.Name, i18nName)
			}
			if info.DisplayName != "fallback-id" {
				t.Errorf("DisplayName = %q for i18n manifest %q, want fallback-id", info.DisplayName, i18nName)
			}
		})
	}
}

// TestReadExtensionManifest_WithLocaleResolution verifies that i18n keys
// are resolved from locale messages.json files when available.
func TestReadExtensionManifest_WithLocaleResolution(t *testing.T) {
	dir := t.TempDir()

	// Create Chrome-style extension structure: extID/version/manifest.json
	extDir := filepath.Join(dir, "extension-id", "1.0.0")
	if err := os.MkdirAll(extDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Write manifest with i18n key
	manifestPath := filepath.Join(extDir, "manifest.json")
	manifestData := map[string]string{"name": "__MSG_extensionName__", "version": "1.0.0"}
	data, _ := json.Marshal(manifestData)
	if err := os.WriteFile(manifestPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	// Create _locales/en/messages.json in the version directory (same as manifest.json)
	localesDir := filepath.Join(extDir, "_locales", "en")
	if err := os.MkdirAll(localesDir, 0755); err != nil {
		t.Fatal(err)
	}

	messagesData := map[string]map[string]string{
		"extensionName": {"message": "My Awesome Extension"},
	}
	messagesJSON, _ := json.Marshal(messagesData)
	if err := os.WriteFile(filepath.Join(localesDir, "messages.json"), messagesJSON, 0644); err != nil {
		t.Fatal(err)
	}

	info := readExtensionManifest(manifestPath, "chrome", "chrome_extensions", "fallback-id")
	if info == nil {
		t.Fatal("expected non-nil SoftwareInfo")
		return // Early return to satisfy staticcheck
	}
	if info.Name != "fallback-id" {
		t.Errorf("Name = %q, want fallback-id (extension ID)", info.Name)
	}
	if info.DisplayName != "My Awesome Extension" {
		t.Errorf("DisplayName = %q, want 'My Awesome Extension' (resolved from locale)", info.DisplayName)
	}
}

// TestReadExtensionManifest_LocaleFallback verifies fallback to other locales
// when preferred locale is not available.
func TestReadExtensionManifest_LocaleFallback(t *testing.T) {
	dir := t.TempDir()

	// Create extension structure
	extDir := filepath.Join(dir, "extension-id", "1.0.0")
	if err := os.MkdirAll(extDir, 0755); err != nil {
		t.Fatal(err)
	}

	manifestPath := filepath.Join(extDir, "manifest.json")
	manifestData := map[string]string{"name": "__MSG_appName__", "version": "2.0"}
	data, _ := json.Marshal(manifestData)
	if err := os.WriteFile(manifestPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	// Create only Spanish locale in the version directory (no English)
	localesDir := filepath.Join(extDir, "_locales", "es")
	if err := os.MkdirAll(localesDir, 0755); err != nil {
		t.Fatal(err)
	}

	messagesData := map[string]map[string]string{
		"appName": {"message": "Mi Extensión"},
	}
	messagesJSON, _ := json.Marshal(messagesData)
	if err := os.WriteFile(filepath.Join(localesDir, "messages.json"), messagesJSON, 0644); err != nil {
		t.Fatal(err)
	}

	info := readExtensionManifest(manifestPath, "chrome", "chrome_extensions", "fallback-id")
	if info == nil {
		t.Fatal("expected non-nil SoftwareInfo")
		return // Early return to satisfy staticcheck
	}
	// Should fall back to Spanish locale when English is not available
	if info.Name != "fallback-id" {
		t.Errorf("Name = %q, want fallback-id (extension ID)", info.Name)
	}
	if info.DisplayName != "Mi Extensión" {
		t.Errorf("DisplayName = %q, want 'Mi Extensión' (fallback to available locale)", info.DisplayName)
	}
}

// TestReadExtensionManifest_MissingLocaleKey verifies fallback to extension ID
// when the locale file exists but doesn't contain the key.
func TestReadExtensionManifest_MissingLocaleKey(t *testing.T) {
	dir := t.TempDir()

	extDir := filepath.Join(dir, "extension-id", "1.0.0")
	if err := os.MkdirAll(extDir, 0755); err != nil {
		t.Fatal(err)
	}

	manifestPath := filepath.Join(extDir, "manifest.json")
	manifestData := map[string]string{"name": "__MSG_unknownKey__", "version": "1.0"}
	data, _ := json.Marshal(manifestData)
	if err := os.WriteFile(manifestPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	// Create locale with different key in the version directory
	localesDir := filepath.Join(extDir, "_locales", "en")
	if err := os.MkdirAll(localesDir, 0755); err != nil {
		t.Fatal(err)
	}

	messagesData := map[string]map[string]string{
		"otherKey": {"message": "Some other message"},
	}
	messagesJSON, _ := json.Marshal(messagesData)
	if err := os.WriteFile(filepath.Join(localesDir, "messages.json"), messagesJSON, 0644); err != nil {
		t.Fatal(err)
	}

	info := readExtensionManifest(manifestPath, "chrome", "chrome_extensions", "fallback-id")
	if info == nil {
		t.Fatal("expected non-nil SoftwareInfo")
		return // Early return to satisfy staticcheck
	}
	// Should fall back to extension ID when key is not found in locale
	if info.Name != "fallback-id" {
		t.Errorf("Name = %q, want fallback-id (key not in locale)", info.Name)
	}
}

// TestReadExtensionManifest_CaseInsensitiveKey verifies that keys are resolved
// regardless of case (e.g., __MSG_APP_NAME__ vs app_name in messages.json)
func TestReadExtensionManifest_CaseInsensitiveKey(t *testing.T) {
	dir := t.TempDir()

	extDir := filepath.Join(dir, "extension-id", "1.0.0")
	if err := os.MkdirAll(extDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Write manifest with uppercase key
	manifestPath := filepath.Join(extDir, "manifest.json")
	manifestData := map[string]string{"name": "__MSG_APP_NAME__", "version": "1.0"}
	data, _ := json.Marshal(manifestData)
	if err := os.WriteFile(manifestPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	// Create locale with lowercase key
	localesDir := filepath.Join(extDir, "_locales", "en")
	if err := os.MkdirAll(localesDir, 0755); err != nil {
		t.Fatal(err)
	}

	messagesData := map[string]map[string]string{
		"app_name": {"message": "Chrome Web Store Payments"},
	}
	messagesJSON, _ := json.Marshal(messagesData)
	if err := os.WriteFile(filepath.Join(localesDir, "messages.json"), messagesJSON, 0644); err != nil {
		t.Fatal(err)
	}

	info := readExtensionManifest(manifestPath, "chrome", "chrome_extensions", "fallback-id")
	if info == nil {
		t.Fatal("expected non-nil SoftwareInfo")
		return // Early return to satisfy staticcheck
	}
	// Should resolve the uppercase manifest key to lowercase locale key
	if info.Name != "fallback-id" {
		t.Errorf("Name = %q, want fallback-id (extension ID)", info.Name)
	}
	if info.DisplayName != "Chrome Web Store Payments" {
		t.Errorf("DisplayName = %q, want 'Chrome Web Store Payments' (case-insensitive match)", info.DisplayName)
	}
}
