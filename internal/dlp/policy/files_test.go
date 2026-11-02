package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

// filesBundle is the draft contract example from #326.
const filesBundle = `{
  "schema_version": 1, "version": "v-files", "enabled": true,
  "modules": {
    "clipboard": {"enabled": true},
    "files": {
      "enabled": true,
      "channels": {"file.removable": true, "file.network_share": true, "file.upload": false, "file.cloud_sync": false},
      "audit_only": false,
      "max_file_bytes": 52428800, "max_text_bytes": 4194304, "scan_timeout_ms": 5000,
      "on_unscannable": "monitor", "on_timeout": "block",
      "egress_apps": {"windows": [{"path": "C:\\Windows\\explorer.exe", "signer": "Microsoft Windows"}], "darwin": [{"bundle_id": "com.apple.finder"}], "linux": ["/usr/bin/nautilus"]},
      "trusted_devices": [{"vendor_id": "0781", "product_id": "5581", "serial": "ABC"}],
      "trusted_shares": ["\\\\corp-fs\\share"],
      "block_message": "Blocked"
    }
  },
  "policies": [
    {"id": "pf", "name": "Cards to USB", "channels": ["file.removable"], "action": "block",
     "detectors": [{"id": "pii.credit_card", "rule_id": "r1", "min_count": 1}],
     "exceptions": {"trusted_devices": [{"vendor_id": "0781", "product_id": "5581"}], "apps": ["/usr/bin/backup"]}},
    {"id": "pc", "name": "Clipboard", "channels": ["clipboard"], "action": "monitor",
     "detectors": [{"id": "pii.email", "rule_id": "r2", "min_count": 1}]}
  ]
}`

func TestDecode_FilesModule(t *testing.T) {
	b, err := Decode([]byte(filesBundle))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	f := b.Modules.Files
	if !f.Enabled || f.IsAuditOnly() || f.OnUnscannable != OnFailMonitor || f.OnTimeout != OnFailBlock {
		t.Errorf("files module = %+v", f)
	}
	if !f.ChannelEnabled(ChannelFileRemovable) || f.ChannelEnabled(ChannelFileUpload) {
		t.Errorf("channels = %v", f.Channels)
	}
	if f.EgressApps["windows"][0].Signer != "Microsoft Windows" || f.EgressApps["darwin"][0].BundleID != "com.apple.finder" ||
		f.EgressApps["linux"][0].Path != "/usr/bin/nautilus" {
		t.Errorf("egress apps = %+v", f.EgressApps)
	}
	if f.TrustedDevices[0].Serial != "ABC" || f.TrustedShares[0] != `\\corp-fs\share` {
		t.Errorf("trusted = %+v %v", f.TrustedDevices, f.TrustedShares)
	}
	ex := b.Policies[0].Exceptions
	if ex.TrustedDevices[0].VendorID != "0781" || ex.Apps[0].Path != "/usr/bin/backup" || ex.FileDecodeError != "" {
		t.Errorf("exceptions = %+v", ex)
	}

	c := Compile(b)
	if len(c.CompileErrors) != 0 {
		t.Fatalf("compile errors: %v", c.CompileErrors)
	}
	if !c.ChannelEnabled(ChannelFileRemovable) || c.ChannelEnabled(ChannelFileCloudSync) {
		t.Error("file channel switches wrong")
	}
	// The clipboard engine only gets clipboard policies, the file engine
	// only file policies.
	if got := c.For(ChannelClipboard); len(got) != 1 || got[0].ID != "pc" {
		t.Errorf("clipboard policies = %v", got)
	}
	if got := c.For(ChannelFileRemovable); len(got) != 1 || got[0].ID != "pf" {
		t.Errorf("file policies = %v", got)
	}
	eng, errs := c.FilesEngine()
	if eng == nil || len(errs) != 0 {
		t.Fatalf("files engine = %v, %v", eng, errs)
	}
	if res := eng.Scan("card 4111 1111 1111 1111"); len(res.Findings) == 0 {
		t.Error("file engine found nothing")
	}
	if res := c.Clipboard.Scan("card 4111 1111 1111 1111"); len(res.Findings) != 0 {
		t.Errorf("clipboard engine ran a file policy: %v", res.Findings)
	}
}

// A files module this agent can't read must not take the clipboard down.
func TestDecode_BadFilesModuleKeepsClipboard(t *testing.T) {
	cases := map[string]string{
		"wrong type":      `"files": {"enabled": true, "channels": ["file.removable"]}`,
		"not an object":   `"files": "on"`,
		"bad egress app":  `"files": {"enabled": true, "egress_apps": {"linux": [42]}}`,
		"bad max bytes":   `"files": {"enabled": true, "max_file_bytes": "50MB"}`,
		"bad audit_only":  `"files": {"enabled": true, "audit_only": "no"}`,
		"bad device list": `"files": {"enabled": true, "trusted_devices": "all"}`,
	}
	for name, files := range cases {
		in := `{"schema_version": 1, "version": "v", "enabled": true,
		  "modules": {"clipboard": {"enabled": true}, ` + files + `},
		  "policies": [{"id": "p", "name": "n", "channels": ["clipboard"], "action": "block",
		    "detectors": [{"id": "pii.credit_card", "rule_id": "r", "min_count": 1}]}]}`
		b, err := Decode([]byte(in))
		if err != nil {
			t.Errorf("%s: Decode failed: %v", name, err)
			continue
		}
		if b.Modules.Files.Enabled || b.Modules.Files.DecodeError == "" || b.Modules.Files.ChannelEnabled(ChannelFileRemovable) {
			t.Errorf("%s: files module = %+v, want off with a decode error", name, b.Modules.Files)
		}
		c := Compile(b)
		if !c.ChannelEnabled(ChannelClipboard) || c.Clipboard == nil {
			t.Errorf("%s: clipboard lost", name)
		}
		if len(c.CompileErrors) == 0 || c.CompileErrors[0].RuleID != "modules.files" {
			t.Errorf("%s: compile errors = %v, want modules.files reported", name, c.CompileErrors)
		}
	}
}

func TestDecode_BadFileExceptionsKeepPolicy(t *testing.T) {
	in := `{"schema_version": 1, "version": "v", "enabled": true, "modules": {"clipboard": {"enabled": true}},
	  "policies": [{"id": "p", "name": "n", "channels": ["clipboard"], "action": "block",
	    "detectors": [{"id": "pii.credit_card", "rule_id": "r", "min_count": 1}],
	    "exceptions": {"source_apps": ["KeePassXC"], "trusted_devices": "all"}}]}`
	b, err := Decode([]byte(in))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	ex := b.Policies[0].Exceptions
	if ex.SourceApps[0] != "KeePassXC" || ex.TrustedDevices != nil || ex.FileDecodeError == "" {
		t.Errorf("exceptions = %+v", ex)
	}
	if c := Compile(b); c.Clipboard == nil || len(c.CompileErrors) != 1 {
		t.Errorf("compile: clipboard %v, errors %v", c.Clipboard, c.CompileErrors)
	}
	// source_apps keeps its old strictness.
	bad := strings.Replace(in, `["KeePassXC"]`, `"KeePassXC"`, 1)
	if _, err := Decode([]byte(bad)); err == nil {
		t.Error("a bad source_apps was accepted")
	}
}

func TestFilesModule_Defaults(t *testing.T) {
	b, err := Decode([]byte(`{"schema_version": 1, "version": "v", "modules": {"files": {"enabled": true, "channels": {"file.removable": true},
	  "max_file_bytes": 999999999999, "max_text_bytes": -1, "scan_timeout_ms": 1, "on_unscannable": "explode", "on_timeout": "monitor"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	f := b.Modules.Files
	if !f.IsAuditOnly() {
		t.Error("a bundle without audit_only must be audit-only")
	}
	if f.MaxFileBytes != MaxFileBytesLimit || f.MaxTextBytes != DefaultMaxTextBytes || f.ScanTimeoutMs != MinScanTimeout {
		t.Errorf("limits = %d %d %d", f.MaxFileBytes, f.MaxTextBytes, f.ScanTimeoutMs)
	}
	// Fail open unless "block" is explicit; on_timeout has no monitor mode.
	if f.OnUnscannable != OnFailAllow || f.OnTimeout != OnFailAllow {
		t.Errorf("fail modes = %q %q", f.OnUnscannable, f.OnTimeout)
	}

	empty, err := Decode([]byte(`{"schema_version": 1, "version": "v"}`))
	if err != nil {
		t.Fatal(err)
	}
	if e := empty.Modules.Files; e.Enabled || e.MaxFileBytes != DefaultMaxFileBytes || e.ScanTimeoutMs != DefaultScanTimeout || e.DecodeError != "" {
		t.Errorf("absent files module = %+v", e)
	}
}

// File channels aren't enforced yet: a bundle with only them must leave DLP
// idle rather than start session helpers with nothing to do.
func TestAnyChannelEnabled_IgnoresFileChannels(t *testing.T) {
	b, err := Decode([]byte(`{"schema_version": 1, "version": "v", "enabled": true,
	  "modules": {"clipboard": {"enabled": false}, "files": {"enabled": true, "channels": {"file.removable": true}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if b.AnyChannelEnabled() || Compile(b).AnyChannelEnabled() {
		t.Error("a files-only bundle counts as an enforced channel")
	}
}

// The service forwards the bundle to helpers as JSON: a re-encoded bundle
// must decode to the same file settings.
func TestFilesModule_RoundTrip(t *testing.T) {
	b, err := Decode([]byte(filesBundle))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := Decode(raw)
	if err != nil {
		t.Fatalf("re-decode: %v", err)
	}
	f, f2 := b.Modules.Files, b2.Modules.Files
	if f2.IsAuditOnly() != f.IsAuditOnly() || !f2.ChannelEnabled(ChannelFileRemovable) || f2.EgressApps["linux"][0].Path != "/usr/bin/nautilus" ||
		b2.Policies[0].Exceptions.Apps[0].Path != "/usr/bin/backup" {
		t.Errorf("round trip changed the module: %+v", f2)
	}
}

func TestIsFileChannel(t *testing.T) {
	for _, ch := range FileChannels {
		if !IsFileChannel(ch) {
			t.Errorf("%s is not a file channel", ch)
		}
	}
	if IsFileChannel(ChannelClipboard) || IsFileChannel("files") {
		t.Error("non-file channel accepted")
	}
}

func TestFileFilters(t *testing.T) {
	in := `{"schema_version": 1, "version": "v", "enabled": true, "modules": {"clipboard": {"enabled": true}},
	  "policies": [
	    {"id": "a", "name": "a", "channels": ["file.removable"], "action": "monitor",
	     "detectors": [{"id": "pii.credit_card", "rule_id": "r", "min_count": 1}],
	     "file_filters": {"types": ["XLSX", ".pdf"], "min_bytes": 10, "max_bytes": 1000}},
	    {"id": "b", "name": "b", "channels": ["file.removable", "clipboard"], "action": "monitor",
	     "detectors": [{"id": "pii.credit_card", "rule_id": "r", "min_count": 1}],
	     "file_filters": {"types": "xlsx"}}]}`
	b, err := Decode([]byte(in))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	f := b.Policies[0].FileFilters
	if len(f.Types) != 2 || f.Types[0] != "xlsx" || f.Types[1] != "pdf" || f.MinBytes != 10 || f.MaxBytes != 1000 {
		t.Errorf("filters %+v", f)
	}
	for size, want := range map[int64]bool{9: false, 10: true, 1000: true, 1001: false} {
		if f.SizeOK(size) != want {
			t.Errorf("SizeOK(%d) != %v", size, want)
		}
	}
	for _, tc := range []struct {
		ext, detected string
		want          bool
	}{
		{"xlsx", "", true},
		{"XLSX", "binary", true},
		{"jpg", "ooxml.xlsx", true}, // renamed: caught by its content
		{"pdf", "pdf", true},
		{"docx", "ooxml.docx", false},
		{"", "text.utf8", false},
	} {
		if got := f.TypeOK(tc.ext, tc.detected); got != tc.want {
			t.Errorf("TypeOK(%q, %q) = %v", tc.ext, tc.detected, got)
		}
	}
	if !(FileFilters{}).TypeOK("anything", "") || !(FileFilters{}).SizeOK(1<<40) {
		t.Error("empty filters filter")
	}
	// Unreadable filters: the policy applies to every file and is reported;
	// the clipboard part of the bundle is untouched.
	bad := b.Policies[1].FileFilters
	if bad.DecodeError == "" || len(bad.Types) != 0 {
		t.Errorf("bad filters %+v", bad)
	}
	c := Compile(b)
	if c.Clipboard == nil || len(c.CompileErrors) != 1 || c.CompileErrors[0].RuleID != "b" {
		t.Errorf("compile: clipboard %v, errors %v", c.Clipboard, c.CompileErrors)
	}
}
