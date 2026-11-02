package filedlp

import (
	"context"

	"sentinelgo/internal/dlp/channel"
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
	// Health reports the hook's state and counters; nil when never started.
	Health() *Health
}

// Options configure an Enforcer.
type Options struct {
	Sink      channel.EventSink
	Exe       string // the agent binary, run as scan workers
	ConfigDir string // holds the local emergency switch, see OffSwitchFile
}

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
	return out
}

// wants reports whether m enables one of the supported channels.
func wants(m policy.FilesModule, supported map[string]bool) bool {
	for ch := range supported {
		if m.ChannelEnabled(ch) {
			return true
		}
	}
	return false
}
