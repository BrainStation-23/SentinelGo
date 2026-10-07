package audio

// Fuzz target for the audio-device output parsers (system_profiler, lspci,
// /proc/asound/cards, lsusb, PowerShell JSON). They parse the output of fixed
// system tools, so the input is less hostile than log lines, but the parsing
// is all field-splitting and must never panic on unexpected output.
//
// The seed corpus runs as an ordinary unit test under `go test ./...`.
// To fuzz: go test -run='^$' -fuzz='^FuzzAudioParsers$' -fuzztime=1m ./internal/osinfo/audio/

import (
	"strings"
	"testing"
)

func FuzzAudioParsers(f *testing.F) {
	for _, s := range []string{
		darwinSample, lspciSample, asoundSample, lsusbSample, winPnpArray, winPnpSingle, winWmiArray,
		"", "\n", ":", "[", "{", "null", "[]", "[null]", `[{"FriendlyName":1}]`,
		" 0 [", " 0 [PCH ]:", "Bus 001 Device 001: ID", "00:1f.3 Audio device [0403]:",
		strings.Repeat("Audio:\n    ", 500),
	} {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, output string) {
		_ = parseDarwinAudioOutput(output)
		_ = parseLinuxLspciOutput(output)
		_ = parseLinuxAsoundCards(output)
		_ = parseLinuxLsusbOutput(output)
		_ = parseWindowsPnpJSON(output)
		_ = parseWindowsWmiJSON(output)
	})
}
