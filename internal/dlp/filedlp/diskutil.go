package filedlp

// Reading what macOS's diskutil and ioreg print (volumes_darwin.go runs
// them). OS-independent, so it is tested on every OS.

import (
	"bytes"
	"fmt"
	"strings"

	"sentinelgo/internal/dlp/events"
)

// diskInfo is what diskutil says about a disk.
type diskInfo struct {
	Removable bool   // external, on a removable bus
	WholeDisk string // disk4
	ReadOnly  bool
	USB       *events.USB
}

// removableProtocols are the buses diskutil reports for removable media.
var removableProtocols = map[string]bool{"USB": true, "Secure Digital": true, "FireWire": true}

// parseDiskutilInfo reads `diskutil info -plist`.
func parseDiskutilInfo(b []byte) (diskInfo, error) {
	v, err := parsePlist(bytes.NewReader(b))
	if err != nil {
		return diskInfo{}, fmt.Errorf("diskutil info: %w", err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return diskInfo{}, fmt.Errorf("diskutil info: not a dict")
	}
	internal := plistBool(m, "Internal")
	proto := plistString(m, "BusProtocol")
	info := diskInfo{
		Removable: !internal && removableProtocols[proto],
		WholeDisk: plistString(m, "ParentWholeDisk"),
		ReadOnly:  m["WritableVolume"] == false,
	}
	return info, nil
}

// usbForDisk finds, in `ioreg -a -l -r -c IOUSBHostDevice`, the USB device
// whose children include the BSD disk wholeDisk, and returns its ids.
func usbForDisk(b []byte, wholeDisk string) *events.USB {
	v, err := parsePlist(bytes.NewReader(b))
	if err != nil {
		return nil
	}
	devices, _ := v.([]any)
	for _, d := range devices {
		m, ok := d.(map[string]any)
		if !ok || !hasBSDName(m, wholeDisk, 0) {
			continue
		}
		usb := &events.USB{Serial: plistString(m, "USB Serial Number")}
		if usb.Serial == "" {
			usb.Serial = plistString(m, "kUSBSerialNumberString")
		}
		if n, ok := plistInt(m, "idVendor"); ok {
			usb.VendorID = fmt.Sprintf("%04x", n)
		}
		if n, ok := plistInt(m, "idProduct"); ok {
			usb.ProductID = fmt.Sprintf("%04x", n)
		}
		if usb.VendorID == "" {
			return nil
		}
		return usb
	}
	return nil
}

func hasBSDName(m map[string]any, name string, depth int) bool {
	if depth > 32 {
		return false
	}
	if plistString(m, "BSD Name") == name {
		return true
	}
	children, _ := m["IORegistryEntryChildren"].([]any)
	for _, c := range children {
		if cm, ok := c.(map[string]any); ok && hasBSDName(cm, name, depth+1) {
			return true
		}
	}
	return false
}

// shareHostDarwin is the host of //user@host/share or host:/path.
func shareHostDarwin(from string) string {
	if rest, ok := strings.CutPrefix(from, "//"); ok {
		host, _, _ := strings.Cut(rest, "/")
		if i := strings.LastIndexByte(host, '@'); i >= 0 {
			host = host[i+1:]
		}
		return host
	}
	if host, _, ok := strings.Cut(from, ":"); ok {
		return host
	}
	return ""
}
