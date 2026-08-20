//go:build windows

package identity

import (
	"context"
	"strings"

	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows/registry"
)

type win32ComputerSystem struct {
	Manufacturer string
}

type win32ComputerSystemProduct struct {
	UUID string
}

type win32SystemEnclosure struct {
	SMBIOSAssetTag string
}

type win32BaseBoard struct {
	SerialNumber string
}

// machineGUIDKey and value follow the well-known per-install identifier
// Windows generates once at setup and never changes; it is the standard
// substitute for a hardware machine ID on this platform.
const (
	machineGUIDKey   = `SOFTWARE\Microsoft\Cryptography`
	machineGUIDValue = "MachineGuid"
)

// platformExtra gathers Windows-only identity fields via native WMI, which is
// the preferred mechanism for plain-WQL-queryable classes (see
// docs/telemetry/03-collection-matrix.md) and roughly an order of magnitude
// cheaper than spawning PowerShell per field.
func platformExtra(_ context.Context) (ex extra) {
	defer func() {
		if r := recover(); r != nil {
			ex.Warnings = append(ex.Warnings, "wmi query panicked")
		}
	}()

	var sources []string

	var cs []win32ComputerSystem
	if err := wmi.Query("SELECT Manufacturer FROM Win32_ComputerSystem", &cs); err == nil && len(cs) > 0 {
		ex.Manufacturer = clean(cs[0].Manufacturer)
		sources = append(sources, "Win32_ComputerSystem")
	} else if err != nil {
		ex.Warnings = append(ex.Warnings, "Win32_ComputerSystem query failed")
	}

	var product []win32ComputerSystemProduct
	if err := wmi.Query("SELECT UUID FROM Win32_ComputerSystemProduct", &product); err == nil && len(product) > 0 {
		ex.DeviceUUID = clean(product[0].UUID)
		sources = append(sources, "Win32_ComputerSystemProduct")
	} else if err != nil {
		ex.Warnings = append(ex.Warnings, "Win32_ComputerSystemProduct query failed")
	}

	var enclosure []win32SystemEnclosure
	if err := wmi.Query("SELECT SMBIOSAssetTag FROM Win32_SystemEnclosure", &enclosure); err == nil && len(enclosure) > 0 {
		ex.AssetTag = clean(enclosure[0].SMBIOSAssetTag)
		sources = append(sources, "Win32_SystemEnclosure")
	} else if err != nil {
		ex.Warnings = append(ex.Warnings, "Win32_SystemEnclosure query failed")
	}

	var board []win32BaseBoard
	if err := wmi.Query("SELECT SerialNumber FROM Win32_BaseBoard", &board); err == nil && len(board) > 0 {
		ex.BoardSerial = clean(board[0].SerialNumber)
		sources = append(sources, "Win32_BaseBoard")
	} else if err != nil {
		ex.Warnings = append(ex.Warnings, "Win32_BaseBoard query failed")
	}

	if guid, err := readMachineGUID(); err == nil {
		ex.MachineID = guid
		sources = append(sources, "registry:MachineGuid")
	} else {
		ex.Warnings = append(ex.Warnings, "MachineGuid registry read failed")
	}

	ex.Source = "wmi:root/cimv2:" + strings.Join(sources, ",")
	return ex
}

// readMachineGUID reads the per-install identifier from the registry via
// x/sys/windows/registry, preferred over shelling out to reg query.
func readMachineGUID() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, machineGUIDKey, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()

	v, _, err := k.GetStringValue(machineGUIDValue)
	if err != nil {
		return "", err
	}
	return clean(v), nil
}
