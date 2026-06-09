package audio

// audio_test.go has no OS-specific file suffix, so it compiles and runs on
// every platform. All functions under test live in parse.go / audio.go which
// are also suffix-free, making them universally testable.

import (
	"testing"
)

// ── inferManufacturer ────────────────────────────────────────────────────────

func TestInferManufacturer(t *testing.T) {
	// inferManufacturer is a pass-through: every name is returned as-is so
	// all devices get a non-empty manufacturer value.
	cases := []string{
		"Realtek High Definition Audio",
		"Intel Corporation HD Audio",
		"NVIDIA Virtual Audio Device (Wave Extensible) (WDM)",
		"USB PnP Sound Device",
		"Generic Audio Adapter",
		"HyperX Cloud II Wireless",
	}
	for _, name := range cases {
		got := inferManufacturer(name)
		if got != name {
			t.Errorf("inferManufacturer(%q) = %q, want identity", name, got)
		}
	}
	// Empty string in → empty string out.
	if got := inferManufacturer(""); got != "" {
		t.Errorf("inferManufacturer(\"\") = %q, want \"\"", got)
	}
}

// ── inferDeviceType ──────────────────────────────────────────────────────────

func TestInferDeviceType(t *testing.T) {
	cases := []struct{ name, want string }{
		{"Speakers (Realtek HD Audio)", "output"},
		{"Headphones", "output"},
		{"HDMI Output", "output"},
		{"SPDIF Out", "output"},
		{"Line Out", "output"},
		{"Playback Device", "output"},
		{"Microphone Array", "input"},
		{"Line In", "input"},
		{"Capture Device", "input"},
		{"Recording Interface", "input"},
		{"USB PnP Sound Device", ""}, // neither keyword
		{"Realtek High Definition Audio", ""},
	}
	for _, c := range cases {
		got := inferDeviceType(c.name)
		if got != c.want {
			t.Errorf("inferDeviceType(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

// ── parseDarwinAudioOutput ───────────────────────────────────────────────────

const darwinSample = `Audio:

    Devices:

        MacBook Pro Microphone:

          Default Input Device: Yes
          Input Channels: 1
          Manufacturer: Apple Inc.
          Current SampleRate: 44100
          Transport: Built-in
          Input Source: MacBook Pro Microphone

        MacBook Pro Speakers:

          Default Output Device: Yes
          Default System Output Device: Yes
          Manufacturer: Apple Inc.
          Output Channels: 2
          Current SampleRate: 44100
          Transport: Built-in
          Output Source: MacBook Pro Speakers

        HyperX Cloud II Wireless:

          Default Input Device: No
          Default Output Device: No
          Manufacturer: Kingston
          Input Channels: 2
          Output Channels: 2
          Current SampleRate: 48000
          Transport: USB
          Input Source: HyperX Cloud II Wireless
          Output Source: HyperX Cloud II Wireless

        Unknown Device:

          Manufacturer:
          Current SampleRate: 44100
`

func TestParseDarwinAudioOutput(t *testing.T) {
	devices := parseDarwinAudioOutput(darwinSample)

	if len(devices) != 4 {
		t.Fatalf("expected 4 devices, got %d: %+v", len(devices), devices)
	}

	cases := []struct {
		desc, mfr, typ string
	}{
		{"MacBook Pro Microphone", "Apple Inc.", "input"},
		{"MacBook Pro Speakers", "Apple Inc.", "output"},
		{"HyperX Cloud II Wireless", "Kingston", "input/output"},
		{"Unknown Device", "Unknown Device", ""},
	}

	for i, c := range cases {
		d := devices[i]
		if d.Description != c.desc {
			t.Errorf("[%d] Description = %q, want %q", i, d.Description, c.desc)
		}
		if d.Manufacturer != c.mfr {
			t.Errorf("[%d] Manufacturer = %q, want %q", i, d.Manufacturer, c.mfr)
		}
		if d.Type != c.typ {
			t.Errorf("[%d] Type = %q, want %q", i, d.Type, c.typ)
		}
	}
}

func TestParseDarwinAudioOutput_Empty(t *testing.T) {
	if got := parseDarwinAudioOutput(""); len(got) != 0 {
		t.Errorf("expected 0 devices for empty input, got %d", len(got))
	}
}

func TestParseDarwinAudioOutput_Dedup(t *testing.T) {
	// Two identical blocks should produce one device.
	input := `
        Realtek USB Audio:

          Manufacturer: Realtek
          Input Source: Realtek USB Audio

        Realtek USB Audio:

          Manufacturer: Realtek
          Input Source: Realtek USB Audio
`
	devices := parseDarwinAudioOutput(input)
	if len(devices) != 1 {
		t.Errorf("expected 1 device after dedup, got %d", len(devices))
	}
}

func TestParseDarwinAudioOutput_InferManufacturer(t *testing.T) {
	// When Manufacturer field is absent, inferManufacturer fills it with the
	// device description (pass-through).
	input := `
        Realtek USB Audio:

          Input Source: Realtek USB Audio
`
	devices := parseDarwinAudioOutput(input)
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}
	if devices[0].Manufacturer != "Realtek USB Audio" {
		t.Errorf("Manufacturer = %q, want %q", devices[0].Manufacturer, "Realtek USB Audio")
	}
}

// ── parseLinuxLspciOutput ────────────────────────────────────────────────────

const lspciSample = `00:00.0 Host bridge [0600]: Intel Corporation 12th Gen Core Processor Host Bridge/DRAM Registers [8086:4601] (rev 02)
00:02.0 VGA compatible controller [0300]: Intel Corporation Alder Lake-P Integrated Graphics Controller [8086:46a6] (rev 0c)
00:1f.3 Audio device [0403]: Intel Corporation Alder Lake PCH-P High Definition Audio Controller [8086:51c8] (rev 01)
01:00.1 Audio device [0403]: NVIDIA Corporation GA106 High Definition Audio Controller [10de:228e] (rev a1)
02:00.0 Network controller [0280]: Intel Corporation Wi-Fi 6 AX201 [8086:a0f0] (rev 1a)`

func TestParseLinuxLspciOutput(t *testing.T) {
	devices := parseLinuxLspciOutput(lspciSample)

	if len(devices) != 2 {
		t.Fatalf("expected 2 audio devices, got %d: %+v", len(devices), devices)
	}

	// Manufacturer is inferred by passing the description through inferManufacturer,
	// which is now a pass-through — so Manufacturer == Description for lspci entries.
	cases := []struct{ desc, mfr string }{
		{"Intel Corporation Alder Lake PCH-P High Definition Audio Controller", "Intel Corporation Alder Lake PCH-P High Definition Audio Controller"},
		{"NVIDIA Corporation GA106 High Definition Audio Controller", "NVIDIA Corporation GA106 High Definition Audio Controller"},
	}
	for i, c := range cases {
		if devices[i].Description != c.desc {
			t.Errorf("[%d] Description = %q, want %q", i, devices[i].Description, c.desc)
		}
		if devices[i].Manufacturer != c.mfr {
			t.Errorf("[%d] Manufacturer = %q, want %q", i, devices[i].Manufacturer, c.mfr)
		}
	}
}

func TestParseLinuxLspciOutput_NoAudio(t *testing.T) {
	input := "00:00.0 Host bridge [0600]: Intel Corporation Host Bridge\n00:14.0 USB controller [0c03]: Intel Corporation"
	if got := parseLinuxLspciOutput(input); len(got) != 0 {
		t.Errorf("expected 0 devices, got %d", len(got))
	}
}

func TestParseLinuxLspciOutput_Dedup(t *testing.T) {
	// Same device described twice should produce one entry.
	line := "00:1f.3 Audio device [0403]: Intel Corporation HD Audio [8086:51c8] (rev 01)"
	devices := parseLinuxLspciOutput(line + "\n" + line)
	if len(devices) != 1 {
		t.Errorf("expected 1 device after dedup, got %d", len(devices))
	}
}

// ── parseLinuxAsoundCards ────────────────────────────────────────────────────

const asoundSample = ` 0 [PCH            ]: HDA-Intel - HDA Intel PCH
                      HDA Intel PCH at 0x603c118000 irq 165
 1 [NVidia         ]: HDA-Intel - HDA NVidia
                      HDA NVidia at 0x83000000 irq 17
 2 [Headset        ]: USB-Audio - HyperX Cloud II Wireless
                      Kingston HyperX Cloud II Wireless at usb-0000:00:14.0-2, full speed`

func TestParseLinuxAsoundCards(t *testing.T) {
	devices := parseLinuxAsoundCards(asoundSample)

	if len(devices) != 3 {
		t.Fatalf("expected 3 devices, got %d: %+v", len(devices), devices)
	}

	// Manufacturer is a pass-through of the description for asound cards entries.
	cases := []struct{ desc, mfr string }{
		{"HDA Intel PCH", "HDA Intel PCH"},
		{"HDA NVidia", "HDA NVidia"},
		{"HyperX Cloud II Wireless", "HyperX Cloud II Wireless"},
	}
	for i, c := range cases {
		if devices[i].Description != c.desc {
			t.Errorf("[%d] Description = %q, want %q", i, devices[i].Description, c.desc)
		}
		if devices[i].Manufacturer != c.mfr {
			t.Errorf("[%d] Manufacturer = %q, want %q", i, devices[i].Manufacturer, c.mfr)
		}
	}
}

func TestParseLinuxAsoundCards_NoDriver(t *testing.T) {
	// Card with no " - " separator uses the full description.
	input := " 0 [Generic]: SomeDriver - Generic Audio Card\n"
	devices := parseLinuxAsoundCards(input)
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}
	if devices[0].Description != "Generic Audio Card" {
		t.Errorf("Description = %q, want %q", devices[0].Description, "Generic Audio Card")
	}
}

func TestParseLinuxAsoundCards_Empty(t *testing.T) {
	if got := parseLinuxAsoundCards(""); len(got) != 0 {
		t.Errorf("expected 0 devices for empty input, got %d", len(got))
	}
}

// ── parseLinuxLsusbOutput ────────────────────────────────────────────────────

const lsusbSample = `Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
Bus 001 Device 003: ID 0bda:5400 Realtek Semiconductor Corp. BillSnap Webcam - Audio
Bus 001 Device 005: ID 046d:0a87 Logitech, Inc. G935 Gaming Headset
Bus 002 Device 002: ID 05e3:0608 Genesys Logic, Inc. Hub`

func TestParseLinuxLsusbOutput(t *testing.T) {
	devices := parseLinuxLsusbOutput(lsusbSample)

	if len(devices) != 2 {
		t.Fatalf("expected 2 audio devices, got %d: %+v", len(devices), devices)
	}

	// lsusb includes the vendor company name in the description string.
	// Manufacturer is a pass-through of that same description.
	cases := []struct{ desc, mfr string }{
		{"Realtek Semiconductor Corp. BillSnap Webcam - Audio", "Realtek Semiconductor Corp. BillSnap Webcam - Audio"},
		{"Logitech, Inc. G935 Gaming Headset", "Logitech, Inc. G935 Gaming Headset"},
	}
	for i, c := range cases {
		if devices[i].Description != c.desc {
			t.Errorf("[%d] Description = %q, want %q", i, devices[i].Description, c.desc)
		}
		if devices[i].Manufacturer != c.mfr {
			t.Errorf("[%d] Manufacturer = %q, want %q", i, devices[i].Manufacturer, c.mfr)
		}
	}
}

func TestParseLinuxLsusbOutput_TooFewFields(t *testing.T) {
	// Lines with fewer than 7 fields must be skipped without panic.
	if got := parseLinuxLsusbOutput("Bus 001 Device 003: ID audio"); len(got) != 0 {
		t.Errorf("expected 0 devices for short line, got %d", len(got))
	}
}

// ── parseWindowsPnpJSON ──────────────────────────────────────────────────────

const winPnpArray = `[
  {"FriendlyName": "Speakers (Realtek High Definition Audio)", "Manufacturer": "Realtek Semiconductor Corp."},
  {"FriendlyName": "Microphone (Realtek High Definition Audio)", "Manufacturer": "Microsoft"},
  {"FriendlyName": "NVIDIA Virtual Audio Device (Wave Extensible) (WDM)", "Manufacturer": "NVIDIA"}
]`

const winPnpSingle = `{"FriendlyName": "Speakers (Realtek High Definition Audio)", "Manufacturer": "Realtek Semiconductor Corp."}`

func TestParseWindowsPnpJSON_Array(t *testing.T) {
	devices := parseWindowsPnpJSON(winPnpArray)

	if len(devices) != 3 {
		t.Fatalf("expected 3 devices, got %d: %+v", len(devices), devices)
	}

	// Speakers → output type inferred from name
	if devices[0].Type != "output" {
		t.Errorf("devices[0].Type = %q, want %q", devices[0].Type, "output")
	}
	// Microsoft manufacturer is replaced by inferManufacturer (the device name).
	if devices[1].Manufacturer == "Microsoft" {
		t.Errorf("devices[1].Manufacturer should have been replaced from 'Microsoft'")
	}
	// Microphone → input type
	if devices[1].Type != "input" {
		t.Errorf("devices[1].Type = %q, want %q", devices[1].Type, "input")
	}
	if devices[2].Manufacturer != "NVIDIA" {
		t.Errorf("devices[2].Manufacturer = %q, want NVIDIA", devices[2].Manufacturer)
	}
}

func TestParseWindowsPnpJSON_Single(t *testing.T) {
	// PowerShell ConvertTo-Json returns a bare object when there is one device.
	devices := parseWindowsPnpJSON(winPnpSingle)
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}
	if devices[0].Description != "Speakers (Realtek High Definition Audio)" {
		t.Errorf("unexpected description: %q", devices[0].Description)
	}
}

func TestParseWindowsPnpJSON_Invalid(t *testing.T) {
	if got := parseWindowsPnpJSON("not json"); len(got) != 0 {
		t.Errorf("expected 0 devices for invalid JSON, got %d", len(got))
	}
}

func TestParseWindowsPnpJSON_Dedup(t *testing.T) {
	input := `[
		{"FriendlyName": "Speakers (Realtek HD Audio)", "Manufacturer": "Realtek"},
		{"FriendlyName": "Speakers (Realtek HD Audio)", "Manufacturer": "Realtek"}
	]`
	devices := parseWindowsPnpJSON(input)
	if len(devices) != 1 {
		t.Errorf("expected 1 device after dedup, got %d", len(devices))
	}
}

// ── parseWindowsWmiJSON ──────────────────────────────────────────────────────

const winWmiArray = `[
  {"Name": "Realtek High Definition Audio", "Manufacturer": "Realtek Semiconductor Corp."},
  {"Name": "NVIDIA Virtual Audio Device (Wave Extensible) (WDM)", "Manufacturer": "NVIDIA"}
]`

func TestParseWindowsWmiJSON_Array(t *testing.T) {
	devices := parseWindowsWmiJSON(winWmiArray)

	if len(devices) != 2 {
		t.Fatalf("expected 2 devices, got %d: %+v", len(devices), devices)
	}
	if devices[0].Manufacturer != "Realtek Semiconductor Corp." {
		t.Errorf("devices[0].Manufacturer = %q, want %q", devices[0].Manufacturer, "Realtek Semiconductor Corp.")
	}
	if devices[1].Manufacturer != "NVIDIA" {
		t.Errorf("devices[1].Manufacturer = %q, want NVIDIA", devices[1].Manufacturer)
	}
}

func TestParseWindowsWmiJSON_MissingName(t *testing.T) {
	// Rows without the Name field must be skipped.
	input := `[{"Manufacturer": "Realtek"}, {"Name": "Speakers", "Manufacturer": "Realtek"}]`
	devices := parseWindowsWmiJSON(input)
	if len(devices) != 1 {
		t.Errorf("expected 1 device (row without Name skipped), got %d", len(devices))
	}
}

// ── integration ──────────────────────────────────────────────────────────────

func TestGet_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live audio collection (shells out to OS commands) in -short mode")
	}
	devices := Get()
	t.Logf("Get() returned %d audio device(s)", len(devices))
	for i, d := range devices {
		t.Logf("  [%d] desc=%q mfr=%q type=%q", i, d.Description, d.Manufacturer, d.Type)
		if d.Description == "" {
			t.Errorf("devices[%d].Description is empty", i)
		}
	}
}
