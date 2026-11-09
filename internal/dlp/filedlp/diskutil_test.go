package filedlp

import (
	"strings"
	"testing"
)

const diskutilUSB = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>BusProtocol</key>
	<string>USB</string>
	<key>DeviceIdentifier</key>
	<string>disk4s1</string>
	<key>Internal</key>
	<false/>
	<key>ParentWholeDisk</key>
	<string>disk4</string>
	<key>Size</key>
	<integer>31914983424</integer>
	<key>VolumeName</key>
	<string>KINGSTON</string>
	<key>WritableVolume</key>
	<true/>
	<key>Nested</key>
	<dict><key>a</key><array><string>x</string><real>1.5</real></array></dict>
</dict>
</plist>`

func TestParseDiskutilInfo(t *testing.T) {
	info, err := parseDiskutilInfo([]byte(diskutilUSB))
	if err != nil || !info.Removable || info.WholeDisk != "disk4" || info.ReadOnly {
		t.Fatalf("%+v %v", info, err)
	}
	internal := strings.Replace(diskutilUSB, "<false/>", "<true/>", 1)
	if info, _ := parseDiskutilInfo([]byte(internal)); info.Removable {
		t.Error("an internal disk is removable")
	}
	nvme := strings.Replace(diskutilUSB, ">USB<", ">PCI-Express<", 1)
	if info, _ := parseDiskutilInfo([]byte(nvme)); info.Removable {
		t.Error("an external PCIe/Thunderbolt disk image counts as removable media")
	}
	ro := strings.Replace(diskutilUSB, "<key>WritableVolume</key>\n\t<true/>", "<key>WritableVolume</key>\n\t<false/>", 1)
	if info, _ := parseDiskutilInfo([]byte(ro)); !info.ReadOnly {
		t.Error("a read-only volume")
	}
	if _, err := parseDiskutilInfo([]byte("<plist><array/></plist>")); err == nil {
		t.Error("not a dict accepted")
	}
	if _, err := parseDiskutilInfo([]byte("garbage")); err == nil {
		t.Error("garbage accepted")
	}
}

const ioregUSB = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<array>
	<dict>
		<key>idVendor</key><integer>1452</integer>
		<key>idProduct</key><integer>4100</integer>
		<key>IORegistryEntryChildren</key>
		<array><dict><key>BSD Name</key><string>disk2</string></dict></array>
	</dict>
	<dict>
		<key>idVendor</key><integer>2385</integer>
		<key>idProduct</key><integer>5734</integer>
		<key>USB Serial Number</key><string>408D5C1B2A3F</string>
		<key>IORegistryEntryChildren</key>
		<array><dict><key>IORegistryEntryChildren</key>
			<array><dict><key>BSD Name</key><string>disk4</string></dict></array>
		</dict></array>
	</dict>
</array>
</plist>`

func TestUSBForDisk(t *testing.T) {
	usb := usbForDisk([]byte(ioregUSB), "disk4")
	if usb == nil || usb.VendorID != "0951" || usb.ProductID != "1666" || usb.Serial != "408D5C1B2A3F" {
		t.Fatalf("%+v", usb)
	}
	if usb := usbForDisk([]byte(ioregUSB), "disk9"); usb != nil {
		t.Errorf("unknown disk: %+v", usb)
	}
	if usb := usbForDisk([]byte("nope"), "disk4"); usb != nil {
		t.Errorf("garbage: %+v", usb)
	}
}

func TestShareHostDarwin(t *testing.T) {
	for from, want := range map[string]string{
		"//ann@files.corp.example/Finance": "files.corp.example",
		"//nas/share":                      "nas",
		"nfs.example:/export/home":         "nfs.example",
		"/dev/disk4s1":                     "",
	} {
		if got := shareHostDarwin(from); got != want {
			t.Errorf("%s: %q want %q", from, got, want)
		}
	}
}

func TestParsePlist_Depth(t *testing.T) {
	deep := strings.Repeat("<array>", maxPlistDepth+2) + strings.Repeat("</array>", maxPlistDepth+2)
	if _, err := parsePlist(strings.NewReader("<plist>" + deep + "</plist>")); err == nil {
		t.Error("too deep accepted")
	}
}
