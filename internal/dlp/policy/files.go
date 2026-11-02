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
	// CopyCorrelation says how the agent links a written file to what it
	// copies (#334). Absent means today\'s behaviour.
	CopyCorrelation CopyCorrelation `json:"copy_correlation"`

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
	m.CopyCorrelation.normalize()
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

// FileFilters narrows a file-channel policy: Types are lowercase extensions
// or detected types (e.g. "xlsx", "ooxml.xlsx", "pdf"), sizes are in bytes.
// Zero values don't filter.
type FileFilters struct {
	Types    []string `json:"types,omitempty"`
	MinBytes int64    `json:"min_bytes,omitempty"`
	MaxBytes int64    `json:"max_bytes,omitempty"`

	// DecodeError is why the filters couldn't be read; the policy then
	// applies to every file (a bad filter must not silence a policy).
	DecodeError string `json:"-"`
}

// UnmarshalJSON never fails: unreadable filters are dropped with
// DecodeError set, so they can't reject a bundle the clipboard depends on.
func (f *FileFilters) UnmarshalJSON(data []byte) error {
	type plain FileFilters
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		*f = FileFilters{DecodeError: fmt.Sprintf("file_filters: %v", err)}
		return nil
	}
	*f = FileFilters(p)
	for i, t := range f.Types {
		f.Types[i] = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(t), "."))
	}
	return nil
}

// SizeOK reports whether a file of size bytes passes the size filters.
func (f FileFilters) SizeOK(size int64) bool {
	return size >= f.MinBytes && (f.MaxBytes <= 0 || size <= f.MaxBytes)
}

// TypeOK reports whether a file passes the type filter, by its extension
// (without the dot) or its detected type: "xlsx" matches a .xlsx file and,
// by content, a renamed one detected as "ooxml.xlsx".
func (f FileFilters) TypeOK(ext, detectedType string) bool {
	if len(f.Types) == 0 {
		return true
	}
	ext = strings.ToLower(ext)
	last := detectedType
	if i := strings.LastIndexByte(detectedType, '.'); i >= 0 {
		last = detectedType[i+1:]
	}
	for _, t := range f.Types {
		if t != "" && (t == ext || t == detectedType || t == last) {
			return true
		}
	}
	return false
}

// What happens to a file found to violate a policy after it was written
// (CopyCorrelation.OnCloseViolation).
const (
	ViolationRecord     = "record"
	ViolationQuarantine = "quarantine" // moved to a root-only folder on the device
	ViolationDelete     = "delete"
)

// Strict modes for removable devices no policy trusts
// (CopyCorrelation.UntrustedDevices).
const (
	UntrustedAllow       = "allow"
	UntrustedReadOnly    = "read_only"
	UntrustedBlockWrites = "block_writes"
)

// Taint window limits, in seconds.
const (
	DefaultTaintWindow = 300
	MinTaintWindow     = 30
	MaxTaintWindow     = 3600
)

// CopyCorrelation is modules.files.copy_correlation (#334, backend
// Compliance-OS#570). Every default keeps the behaviour from before it.
type CopyCorrelation struct {
	ScanOnClose        *bool  `json:"scan_on_close"`        // default true
	OnCloseViolation   string `json:"on_close_violation"`   // record | quarantine | delete
	ProcessTaint       bool   `json:"process_taint"`        // default false
	TaintWindowSeconds int    `json:"taint_window_seconds"` // 30 – 3600, default 300
	OSCopyEvents       *bool  `json:"os_copy_events"`       // default true (macOS)
	UntrustedDevices   string `json:"untrusted_devices"`    // allow | read_only | block_writes

	// DecodeError is why the block couldn't be read; the defaults apply.
	DecodeError string `json:"-"`
}

// UnmarshalJSON never fails: an unreadable block falls back to the
// defaults with DecodeError set, so it can't turn file DLP off.
func (c *CopyCorrelation) UnmarshalJSON(data []byte) error {
	type plain CopyCorrelation
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		*c = CopyCorrelation{DecodeError: fmt.Sprintf("modules.files.copy_correlation: %v", err)}
		return nil
	}
	*c = CopyCorrelation(p)
	return nil
}

func (c *CopyCorrelation) normalize() {
	switch c.OnCloseViolation {
	case ViolationQuarantine, ViolationDelete:
	default:
		c.OnCloseViolation = ViolationRecord
	}
	switch c.UntrustedDevices {
	case UntrustedReadOnly, UntrustedBlockWrites:
	default:
		c.UntrustedDevices = UntrustedAllow
	}
	if c.TaintWindowSeconds <= 0 {
		c.TaintWindowSeconds = DefaultTaintWindow
	}
	c.TaintWindowSeconds = min(max(c.TaintWindowSeconds, MinTaintWindow), MaxTaintWindow)
}

// ScansOnClose reports whether files are scanned after they are written to
// a monitored destination (the default).
func (c CopyCorrelation) ScansOnClose() bool { return c.ScanOnClose == nil || *c.ScanOnClose }

// UsesOSCopyEvents reports whether OS copy events are used where the OS has
// them (the default).
func (c CopyCorrelation) UsesOSCopyEvents() bool { return c.OSCopyEvents == nil || *c.OSCopyEvents }
