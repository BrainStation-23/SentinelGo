package filedlp

// Which drive letters are removable media (#330). USB hard disks and many
// card readers report DRIVE_FIXED, so a volume is classified by the bus its
// disk sits on (IOCTL_STORAGE_QUERY_PROPERTY), not by GetDriveType. The USB
// vendor, product and serial come from the device tree: the volume's disk
// interface → its device instance → up the parents to the USB device
// (USB\VID_xxxx&PID_yyyy\serial). Everything is user-mode Win32 through
// x/sys/windows: no driver, no cgo.

import (
	"encoding/binary"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
)

// IOCTLs and storage constants (winioctl.h).
const (
	ioctlStorageQueryProperty   = 0x002D1400
	ioctlStorageGetDeviceNumber = 0x002D1080
	storageDeviceProperty       = 0 // STORAGE_PROPERTY_ID
	propertyStandardQuery       = 0 // STORAGE_QUERY_TYPE

	busType1394 = 0x4
	busTypeUsb  = 0x7
	busTypeSd   = 0xC
	busTypeMmc  = 0xD

	driveRemovable = 2
	driveFixed     = 3
)

// guidDevinterfaceDisk is GUID_DEVINTERFACE_DISK.
var guidDevinterfaceDisk = windows.GUID{Data1: 0x53f56307, Data2: 0xb6bf, Data3: 0x11d0,
	Data4: [8]byte{0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b}}

// devpkeyDeviceInstanceID is DEVPKEY_Device_InstanceId.
var devpkeyDeviceInstanceID = struct {
	FmtID windows.GUID
	PID   uint32
}{windows.GUID{Data1: 0x78c34fc8, Data2: 0x104a, Data3: 0x4aca, Data4: [8]byte{0x9e, 0xa4, 0x52, 0x4d, 0x52, 0x99, 0x6e, 0x57}}, 256}

var (
	cfgmgr32                         = windows.NewLazySystemDLL("cfgmgr32.dll")
	procCMGetDeviceInterfacePropertW = cfgmgr32.NewProc("CM_Get_Device_Interface_PropertyW")
	procCMLocateDevNodeW             = cfgmgr32.NewProc("CM_Locate_DevNodeW")
	procCMGetParent                  = cfgmgr32.NewProc("CM_Get_Parent")
	procCMGetDeviceIDW               = cfgmgr32.NewProc("CM_Get_Device_IDW")
)

// winVolume is a drive letter that is removable media.
type winVolume struct {
	Destination
	DiskNumber uint32
	ReadOnly   bool // the file system is mounted read-only now
}

// Test seams: the drive letters and how one is described.
var (
	listVolumes    = removableVolumes
	removableBuses = map[uint32]bool{busTypeUsb: true, busTypeSd: true, busTypeMmc: true, busType1394: true}
)

// removableVolumes lists the drive letters on removable buses, except the
// one Windows runs from (Windows To Go boots from USB).
func removableVolumes() []winVolume {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	sys := strings.ToUpper(systemDriveLetter())
	var out []winVolume
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		letter := string(rune('A' + i))
		if letter == sys {
			continue
		}
		if v, ok := describeVolume(letter + `:\`); ok {
			out = append(out, v)
		}
	}
	return out
}

func systemDriveLetter() string {
	dir, err := windows.GetSystemWindowsDirectory()
	if err != nil || len(dir) < 2 || dir[1] != ':' {
		return "C"
	}
	return dir[:1]
}

// describeVolume classifies root (`E:\`); ok is false unless it is on a
// removable bus.
func describeVolume(root string) (winVolume, bool) {
	rootp, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return winVolume{}, false
	}
	if t := windows.GetDriveType(rootp); t != driveRemovable && t != driveFixed {
		return winVolume{}, false // network, optical and RAM drives are other channels
	}
	h, err := openVolume(root, 0)
	if err != nil {
		return winVolume{}, false
	}
	defer func() { _ = windows.CloseHandle(h) }()
	bus, ok := busType(h)
	if !ok || !removableBuses[bus] {
		return winVolume{}, false
	}
	v := winVolume{Destination: Destination{Channel: policy.ChannelFileRemovable, Type: TypeRemovable, Mount: root}}
	if n, ok := deviceNumber(h); ok {
		v.DiskNumber = n
		v.USB = usbIdentity(n)
	}
	var label [windows.MAX_PATH + 1]uint16
	var flags uint32
	if windows.GetVolumeInformation(rootp, &label[0], uint32(len(label)), nil, nil, &flags, nil, 0) == nil {
		v.VolumeLabel = windows.UTF16ToString(label[:])
		v.ReadOnly = flags&windows.FILE_READ_ONLY_VOLUME != 0
	}
	var guid [windows.MAX_PATH + 1]uint16
	if windows.GetVolumeNameForVolumeMountPoint(rootp, &guid[0], uint32(len(guid))) == nil {
		v.Source = windows.UTF16ToString(guid[:])
	} else {
		v.Source = root
	}
	return v, true
}

// openVolume opens \\.\X: with access (0 is enough for the queries).
func openVolume(root string, access uint32) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(`\\.\` + strings.TrimSuffix(root, `\`))
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
}

// busType asks for the STORAGE_DEVICE_DESCRIPTOR's BusType.
func busType(h windows.Handle) (uint32, bool) {
	q := [12]byte{} // STORAGE_PROPERTY_QUERY: PropertyId, QueryType, AdditionalParameters (padded)
	binary.LittleEndian.PutUint32(q[0:], storageDeviceProperty)
	binary.LittleEndian.PutUint32(q[4:], propertyStandardQuery)
	var out [1024]byte
	var n uint32
	if err := windows.DeviceIoControl(h, ioctlStorageQueryProperty, &q[0], uint32(len(q)), &out[0], uint32(len(out)), &n, nil); err != nil {
		return 0, false
	}
	return parseBusType(out[:n])
}

// parseBusType reads BusType from a STORAGE_DEVICE_DESCRIPTOR.
func parseBusType(b []byte) (uint32, bool) {
	const busOff = 28
	if len(b) < busOff+4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b[busOff:]), true
}

// deviceNumber is the disk number of a volume or disk handle.
func deviceNumber(h windows.Handle) (uint32, bool) {
	var out [12]byte // STORAGE_DEVICE_NUMBER: DeviceType, DeviceNumber, PartitionNumber
	var n uint32
	if err := windows.DeviceIoControl(h, ioctlStorageGetDeviceNumber, nil, 0, &out[0], uint32(len(out)), &n, nil); err != nil || n < 8 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(out[4:]), true
}

// usbIdentity finds the USB device that disk number n belongs to; nil when
// it isn't on USB or can't be found.
func usbIdentity(n uint32) *events.USB {
	paths, err := windows.CM_Get_Device_Interface_List("", &guidDevinterfaceDisk, windows.CM_GET_DEVICE_INTERFACE_LIST_PRESENT)
	if err != nil {
		return nil
	}
	for _, p := range paths {
		pp, err := windows.UTF16PtrFromString(p)
		if err != nil {
			continue
		}
		h, err := windows.CreateFile(pp, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
		if err != nil {
			continue
		}
		num, ok := deviceNumber(h)
		_ = windows.CloseHandle(h)
		if !ok || num != n {
			continue
		}
		id, ok := interfaceInstanceID(pp)
		if !ok {
			return nil
		}
		return usbAncestor(id)
	}
	return nil
}

// interfaceInstanceID is the device instance ID behind an interface path.
func interfaceInstanceID(iface *uint16) (string, bool) {
	var propType uint32
	buf := make([]uint16, 512)
	size := uint32(len(buf) * 2)
	r, _, _ := procCMGetDeviceInterfacePropertW.Call(uintptr(unsafe.Pointer(iface)), uintptr(unsafe.Pointer(&devpkeyDeviceInstanceID)),
		uintptr(unsafe.Pointer(&propType)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	if r != 0 {
		return "", false
	}
	return windows.UTF16ToString(buf), true
}

// usbAncestor walks up from instance id to the first USB device (skipping a
// composite device's interface, …&MI_xx) and parses its ids.
func usbAncestor(id string) *events.USB {
	idp, err := windows.UTF16PtrFromString(id)
	if err != nil {
		return nil
	}
	var inst uint32
	if r, _, _ := procCMLocateDevNodeW.Call(uintptr(unsafe.Pointer(&inst)), uintptr(unsafe.Pointer(idp)), 0); r != 0 {
		return nil
	}
	for depth := 0; depth < 8; depth++ {
		buf := make([]uint16, 512)
		if r, _, _ := procCMGetDeviceIDW.Call(uintptr(inst), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0); r != 0 {
			return nil
		}
		if usb, ok := parseUSBInstanceID(windows.UTF16ToString(buf)); ok {
			return usb
		}
		var parent uint32
		if r, _, _ := procCMGetParent.Call(uintptr(unsafe.Pointer(&parent)), uintptr(inst), 0); r != 0 {
			return nil
		}
		inst = parent
	}
	return nil
}

// parseUSBInstanceID reads USB\VID_0781&PID_5567\4C530001234: vendor and
// product in hex, and the serial when the device has one. Windows makes up
// an id with '&' in it for devices without a serial, so that isn't one. An
// interface of a composite device (…&MI_00) is not the device itself.
func parseUSBInstanceID(id string) (*events.USB, bool) {
	parts := strings.Split(id, `\`)
	if len(parts) < 2 || !strings.EqualFold(parts[0], "USB") {
		return nil, false
	}
	usb := &events.USB{}
	for _, kv := range strings.Split(parts[1], "&") {
		k, v, ok := strings.Cut(kv, "_")
		if !ok {
			continue
		}
		switch strings.ToUpper(k) {
		case "VID":
			usb.VendorID = strings.ToLower(v)
		case "PID":
			usb.ProductID = strings.ToLower(v)
		case "MI":
			return nil, false
		}
	}
	if usb.VendorID == "" || usb.ProductID == "" {
		return nil, false
	}
	if len(parts) >= 3 && parts[2] != "" && !strings.Contains(parts[2], "&") {
		usb.Serial = parts[2]
	}
	return usb, true
}
