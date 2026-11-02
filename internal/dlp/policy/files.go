package policy

import (
	"encoding/json"
	"fmt"
	"strings"
)

// File DLP channels (contract #326). No agent enforces them yet: they are
// parsed so the scan engine (internal/dlp/filescan) and the OS hooks can be
// built against the agreed shape.
const (
	ChannelFileRemovable    = "file.removable"
	ChannelFileNetworkShare = "file.network_share"
	ChannelFileUpload       = "file.upload"
	ChannelFileCloudSync    = "file.cloud_sync"
)

// FileChannels lists the file channels this agent knows.
var FileChannels = []string{ChannelFileRemovable, ChannelFileNetworkShare, ChannelFileUpload, ChannelFileCloudSync}

// IsFileChannel reports whether channel is one of the file channels.
func IsFileChannel(channel string) bool { return strings.HasPrefix(channel, "file.") }

// What a file channel does with a file it couldn't scan or didn't finish in
// time (FilesModule.OnUnscannable / OnTimeout).
const (
	OnFailAllow   = "allow"
	OnFailBlock   = "block"
	OnFailMonitor = "monitor" // allow and record an event (on_unscannable only)
)

// File limits and defaults applied when decoding a bundle.
const (
	DefaultMaxFileBytes = 50 << 20
	MaxFileBytesLimit   = 256 << 20
	DefaultMaxTextBytes = 4 << 20
	MaxTextBytesLimit   = 16 << 20
	DefaultScanTimeout  = 5000 // ms
	MinScanTimeout      = 100
	MaxScanTimeout      = 60000
)

// FilesModule configures the file channels (bundle modules.files).
type FilesModule struct {
	Enabled  bool            `json:"enabled"`
	Channels map[string]bool `json:"channels"`
	// AuditOnly records events but never blocks. A bundle that leaves it out
	// is audit-only: blocking must be switched on explicitly.
	AuditOnly      *bool            `json:"audit_only"`
	MaxFileBytes   int64            `json:"max_file_bytes"`
	MaxTextBytes   int              `json:"max_text_bytes"`
	ScanTimeoutMs  int              `json:"scan_timeout_ms"`
	OnUnscannable  string           `json:"on_unscannable"`
	OnTimeout      string           `json:"on_timeout"`
	EgressApps     map[string][]App `json:"egress_apps"` // by GOOS: windows, darwin, linux
	TrustedDevices []Device         `json:"trusted_devices"`
	TrustedShares  []string         `json:"trusted_shares"`
	BlockMessage   string           `json:"block_message"`
	WarnMessage    string           `json:"warn_message"`

	// DecodeError is why modules.files couldn't be read. The module is then
	// off, and the rest of the bundle (the clipboard) is unaffected.
	DecodeError string `json:"-"`
}

// App identifies an application by signer, bundle id or path; never by
// display name alone. The draft contract leaves the element shape open, so a
// plain string is accepted as a path.
type App struct {
	Path     string `json:"path,omitempty"`
	Signer   string `json:"signer,omitempty"`
	BundleID string `json:"bundle_id,omitempty"`
	Name     string `json:"name,omitempty"`
}

// UnmarshalJSON accepts "path" or {"path": …, "signer": …, …}.
func (a *App) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*a = App{Path: s}
		return nil
	}
	type plain App
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*a = App(p)
	return nil
}

// Device is a USB device trusted by vendor, product and (optionally) serial.
type Device struct {
	VendorID  string `json:"vendor_id"`
	ProductID string `json:"product_id"`
	Serial    string `json:"serial,omitempty"`
}

// UnmarshalJSON decodes modules.files without ever failing: a module this
// agent can't read is kept off with DecodeError set, so a contract mismatch
// in the (still draft) file module can't take the clipboard down with it.
func (m *FilesModule) UnmarshalJSON(data []byte) error {
	type plain FilesModule
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		*m = FilesModule{DecodeError: fmt.Sprintf("modules.files: %v", err)}
		return nil
	}
	*m = FilesModule(p)
	return nil
}

// IsAuditOnly reports whether the module may only record (the default).
func (m *FilesModule) IsAuditOnly() bool { return m.AuditOnly == nil || *m.AuditOnly }

// ChannelEnabled reports whether the module and channel are both on.
func (m *FilesModule) ChannelEnabled(channel string) bool {
	return m.Enabled && m.DecodeError == "" && m.Channels[channel]
}

// normalize fills defaults and clamps limits. Fail-open is the default
// (#329): only an explicit "block" turns a failed scan into a block.
func (m *FilesModule) normalize() {
	if m.DecodeError != "" {
		m.Enabled = false
	}
	if m.MaxFileBytes <= 0 {
		m.MaxFileBytes = DefaultMaxFileBytes
	}
	m.MaxFileBytes = min(m.MaxFileBytes, MaxFileBytesLimit)
	if m.MaxTextBytes <= 0 {
		m.MaxTextBytes = DefaultMaxTextBytes
	}
	m.MaxTextBytes = min(m.MaxTextBytes, MaxTextBytesLimit)
	if m.ScanTimeoutMs <= 0 {
		m.ScanTimeoutMs = DefaultScanTimeout
	}
	m.ScanTimeoutMs = min(max(m.ScanTimeoutMs, MinScanTimeout), MaxScanTimeout)
	switch m.OnUnscannable {
	case OnFailBlock, OnFailMonitor:
	default:
		m.OnUnscannable = OnFailAllow
	}
	if m.OnTimeout != OnFailBlock {
		m.OnTimeout = OnFailAllow
	}
}

// fileExceptions are the file-channel fields of a policy's exceptions.
type fileExceptions struct {
	TrustedDevices []Device `json:"trusted_devices"`
	TrustedShares  []string `json:"trusted_shares"`
	Apps           []App    `json:"apps"`
}

// UnmarshalJSON reads source_apps as before (a bad value still rejects the
// bundle, as it always has) and the file fields tolerantly: they're dropped,
// with FileDecodeError set, rather than rejecting a bundle the clipboard
// depends on.
func (e *Exceptions) UnmarshalJSON(data []byte) error {
	var base struct {
		SourceApps []string `json:"source_apps"`
	}
	if err := json.Unmarshal(data, &base); err != nil {
		return err
	}
	*e = Exceptions{SourceApps: base.SourceApps}
	var f fileExceptions
	if err := json.Unmarshal(data, &f); err != nil {
		e.FileDecodeError = fmt.Sprintf("exceptions: %v", err)
		return nil
	}
	e.TrustedDevices, e.TrustedShares, e.Apps = f.TrustedDevices, f.TrustedShares, f.Apps
	return nil
}
