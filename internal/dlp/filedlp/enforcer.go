package filedlp

import (
	"context"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/ipc"
	"sentinelgo/internal/dlp/policy"
	"sentinelgo/internal/dlp/scanworker"
)

// Enforcer runs file DLP on this platform: the OS hook, the scan workers and
// the Decider. The DLP Manager drives it like the session supervisor.
type Enforcer interface {
	// Apply switches to c and starts or stops the hook to match its files
	// module. It is called again with every new policy.
	Apply(ctx context.Context, c *policy.Compiled)
	// Stop stops the hook and the workers. Safe to call when not running.
	Stop()
	// Wants reports whether a files module enables a file channel this
	// platform monitors.
	Wants(m policy.FilesModule) bool
	// Capabilities reports each enabled file channel's capability
	// ("supported" / "unsupported:<reason>"); nil when the files module is off.
	Capabilities() map[string]string
	// CopyCorrelation reports what each copy correlation method can do here
	// (capabilities.copy_correlation); nil when the files module is off.
	CopyCorrelation() map[string]string
	// Health reports the hook's state and counters; nil when never started.
	Health() *Health
}

// UserFileTaker is an Enforcer that decides files the session helpers hand
// over (Windows network shares and sync folders, #330).
type UserFileTaker interface {
	TakeUserFile(from ipc.Identity, f ipc.UserFile)
}

// Options configure an Enforcer.
type Options struct {
	Sink      channel.EventSink
	Exe       string // the agent binary, run as scan workers
	ConfigDir string // holds the local emergency switch, see OffSwitchFile
	// Notifier tells the user whose process caused a block, removal or
	// warning (#336); nil tells nobody. When it is also an Asker, a
	// block_override block opens the override dialog.
	Notifier UserNotifier
	// RequestException sends an exception request to the backend; nil
	// means the dialog doesn't offer one.
	RequestException func(context.Context, ExceptionRequest) error
	// NetworkTaint cuts an egress app's network after it opened a file a
	// file.upload policy would block (taint block, #427; Windows); nil
	// means no taint blocks.
	NetworkTaint NetworkTainter
}

// CapabilityBlockOverride tells the backend this agent asks for a reason on
// a block_override block (Compliance-OS#581); without it the backend sends
// such policies as block.
const CapabilityBlockOverride = "dlp_block_override_v1"

// OffSwitchFile, when it exists in the config directory, turns file DLP off
// on this device without the backend (support's emergency switch, #329):
// the hook stops watching within a few seconds; deleting it turns it back on.
const OffSwitchFile = "dlp-files-off"

// Health is file DLP's state for the status report.
type Health struct {
	State      string            `json:"state"` // running, stopped, disabled_locally, unavailable:<reason>
	Mounts     int               `json:"mounts"`
	Dropped    uint64            `json:"dropped"`    // events lost to a full queue
	Overflows  uint64            `json:"overflows"`  // kernel queue overflows
	Unreadable uint64            `json:"unreadable"` // events without a readable file
	Stats      Stats             `json:"stats"`
	Workers    scanworker.Health `json:"workers"`
	// Process taint: processes tracked, and opens lost to its queue
	// overflowing (it has its own queue, so destination events never are).
	TaintProcesses int    `json:"taint_processes,omitempty"`
	TaintOverflows uint64 `json:"taint_overflows,omitempty"`
	// TaintBlockDropped counts egress app opens not judged because the
	// queue was full (taint blocks, #427).
	TaintBlockDropped uint64 `json:"taint_block_dropped,omitempty"`
	// Blocking is the permission hook that holds file creation while the
	// agent decides (Linux, #333); nil where there is none.
	Blocking *BlockingHealth `json:"blocking,omitempty"`
	// DeepInspection is the upload channel's HTTPS inspection
	// (uploadproxy.Status, #344); nil when it never started.
	DeepInspection any `json:"deep_inspection,omitempty"`
	// NetworkControl is the network controls' state (netctl.Status, #427);
	// nil when they are off.
	NetworkControl any `json:"network_control,omitempty"`
	// AtRest is at-rest classification's state (#331 part 2); nil where it
	// never ran.
	AtRest *AtRestStatus `json:"at_rest,omitempty"`
	// Summary is each file channel's events since the agent started (#430),
	// filled in by the DLP Manager from its Tally; nil without one.
	Summary *Summary `json:"summary,omitempty"`
}

// Hook states.
const (
	stateRunning  = "running"
	stateStopped  = "stopped"
	stateLocalOff = "disabled_locally"
)

// capability turns a hook state into a channel capability.
func capability(state string, workers scanworker.Health) string {
	switch {
	case workers.Disabled:
		return "unsupported:scan_worker_failed"
	case state == stateRunning:
		return "supported"
	case state == stateLocalOff:
		return "unsupported:disabled_locally"
	case len(state) > len("unavailable:") && state[:len("unavailable:")] == "unavailable:":
		return "unsupported:" + state[len("unavailable:"):]
	default:
		return "unsupported:not_running"
	}
}

// channelCapabilities builds Capabilities for a platform that monitors the
// channels in supported.
func channelCapabilities(c *policy.Compiled, supported map[string]bool, state string, workers scanworker.Health) map[string]string {
	if c == nil || !c.Modules.Files.Enabled || c.Modules.Files.DecodeError != "" {
		return nil
	}
	out := map[string]string{}
	for _, ch := range policy.FileChannels {
		if !c.Modules.Files.ChannelEnabled(ch) {
			continue
		}
		if supported[ch] {
			out[ch] = capability(state, workers)
		} else {
			out[ch] = "unsupported:not_implemented"
		}
	}
	if c.Modules.Files.WantsAtRest() {
		out[CapAtRest] = "unsupported:not_on_windows" // the Windows hook reports its own
	}
	return out
}

// wants reports whether m enables one of the supported channels with a
// method this hook has on: scanning after the write, or (removable drives)
// the untrusted device mode.
func wants(m policy.FilesModule, supported map[string]bool) bool {
	cc := m.CopyCorrelation
	for ch := range supported {
		if !m.ChannelEnabled(ch) {
			continue
		}
		if cc.ScansOnClose() || ch == policy.ChannelFileRemovable && cc.UntrustedDevices != policy.UntrustedAllow {
			return true
		}
	}
	return false
}

// Copy correlation methods, as reported in capabilities.copy_correlation.
const (
	MethodScanOnClose      = "scan_on_close"
	MethodProcessTaint     = "process_taint"
	MethodOSCopyEvents     = "os_copy_events"
	MethodUntrustedDevices = "untrusted_devices"
)

// copyCorrelationCapabilities builds CopyCorrelation from the methods this
// hook implements (methods maps a method to "" when it does, or to why it
// can't) and the hook's state. Methods not in the map aren't implemented yet.
func copyCorrelationCapabilities(c *policy.Compiled, methods map[string]string, state string, workers scanworker.Health) map[string]string {
	if c == nil || !c.Modules.Files.Enabled || c.Modules.Files.DecodeError != "" {
		return nil
	}
	out := map[string]string{}
	for _, m := range []string{MethodScanOnClose, MethodProcessTaint, MethodOSCopyEvents, MethodUntrustedDevices} {
		reason, ok := methods[m]
		switch {
		case !ok:
			out[m] = "unsupported:not_implemented"
		case reason != "":
			out[m] = "unsupported:" + reason
		default:
			out[m] = capability(state, workers)
		}
	}
	return out
}
