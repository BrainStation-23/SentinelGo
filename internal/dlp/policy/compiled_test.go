package policy

import "testing"

func TestCompiledChannelEnabled(t *testing.T) {
	c := Compile(&Bundle{Modules: Modules{Clipboard: ClipboardModule{Enabled: true}}})
	if !c.ChannelEnabled(ChannelClipboard) || !c.AnyChannelEnabled() {
		t.Error("clipboard module on, but channel reported off")
	}
	if c.ChannelEnabled("usb") {
		t.Error("unknown channel reported on")
	}

	off := Compile(&Bundle{})
	if off.ChannelEnabled(ChannelClipboard) || off.AnyChannelEnabled() {
		t.Error("clipboard module off, but channel reported on")
	}
}
