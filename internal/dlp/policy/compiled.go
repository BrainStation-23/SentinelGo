package policy

// Compiled is a bundle in the form channels enforce. For now it carries the
// bundle's settings and policies as they are; compiling detectors and regexes
// (and reporting compile errors) is added with policy sync (#260).
type Compiled struct {
	Version      string
	EvidenceMode string
	Modules      Modules
	Policies     []Policy
}

// Compile turns b into its enforceable form. b must not be nil.
func Compile(b *Bundle) *Compiled {
	return &Compiled{
		Version:      b.Version,
		EvidenceMode: b.EvidenceMode,
		Modules:      b.Modules,
		Policies:     b.Policies,
	}
}

// ChannelEnabled reports whether the module for channel is switched on. An
// unknown channel is off.
func (c *Compiled) ChannelEnabled(channel string) bool {
	switch channel {
	case ChannelClipboard:
		return c.Modules.Clipboard.Enabled
	default:
		return false
	}
}

// AnyChannelEnabled reports whether at least one known channel is switched on.
func (c *Compiled) AnyChannelEnabled() bool {
	return c.ChannelEnabled(ChannelClipboard)
}

// ChannelClipboard is the clipboard channel's name in bundles and events.
const ChannelClipboard = "clipboard"
