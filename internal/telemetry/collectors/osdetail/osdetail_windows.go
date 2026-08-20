//go:build windows

package osdetail

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/yusufpapurcu/wmi"
	"golang.org/x/sys/windows/registry"

	tel "sentinelgo/internal/telemetry"
)

type win32SoftwareLicensingProduct struct {
	LicenseStatus uint32
}

// rebootCheck is one registry location whose presence signals a pending
// reboot. value is empty when the KEY's mere existence is the signal
// (Component Based Servicing / Windows Update markers); when set, that named
// value under the key is checked instead (PendingFileRenameOperations, a
// value under Session Manager, not its own key).
type rebootCheck struct {
	root   registry.Key
	path   string
	value  string
	reason string
}

// windowsRebootChecks mirrors the registry triple documented in
// docs/telemetry/03-collection-matrix.md: CBS RebootPending, Windows Update
// RebootRequired, and PendingFileRenameOperations.
var windowsRebootChecks = []rebootCheck{
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`, "", "component_based_servicing"},
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`, "", "windows_update"},
	{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, "PendingFileRenameOperations", "pending_file_rename"},
}

func platformExtra(_ context.Context) (ex extra) {
	defer func() {
		if r := recover(); r != nil {
			ex.Warnings = append(ex.Warnings, "wmi query panicked")
		}
	}()

	var sources []string

	if install, err := readInstallDate(); err == nil {
		ex.InstallDate = install
		sources = append(sources, "registry:InstallDate")
	} else {
		ex.Warnings = append(ex.Warnings, "InstallDate registry read failed")
	}

	pending, reason, err := checkPendingReboot()
	if err != nil {
		ex.Warnings = append(ex.Warnings, "pending-reboot registry check failed")
	} else {
		p := pending
		ex.PendingReboot = &p
		ex.PendingRebootReason = reason
		sources = append(sources, "registry:reboot-pending")
	}

	if status, err := readActivationStatus(); err == nil {
		ex.ActivationStatus = status
		sources = append(sources, "wmi:SoftwareLicensingProduct")
	} else {
		ex.Warnings = append(ex.Warnings, "SoftwareLicensingProduct query failed")
	}

	ex.Source = strings.Join(sources, ", ")
	return ex
}

// readInstallDate reads the per-install timestamp Windows Setup writes once
// and never updates, stored as a Unix epoch DWORD.
func readInstallDate() (string, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()

	v, _, err := k.GetIntegerValue("InstallDate")
	if err != nil {
		return "", err
	}
	return time.Unix(int64(v), 0).UTC().Format(time.RFC3339), nil
}

// checkPendingReboot checks the three registry locations in order and
// reports the first one found. A "not found" on a location is not pending;
// any other error (e.g. permission denied) is inconclusive and returned so
// the caller reports undetermined rather than a guessed false.
func checkPendingReboot() (pending bool, reason string, err error) {
	for _, check := range windowsRebootChecks {
		k, openErr := registry.OpenKey(check.root, check.path, registry.QUERY_VALUE)
		if openErr != nil {
			if errors.Is(openErr, registry.ErrNotExist) {
				continue
			}
			return false, "", openErr
		}

		if check.value == "" {
			k.Close()
			return true, check.reason, nil
		}

		_, _, valErr := k.GetStringsValue(check.value)
		k.Close()
		if valErr == nil {
			return true, check.reason, nil
		}
		if !errors.Is(valErr, registry.ErrNotExist) {
			return false, "", valErr
		}
	}
	return false, "", nil
}

// readActivationStatus queries the Windows OS license specifically —
// ApplicationID '55c92734-d682-4d71-983e-d6ec3f16059f' is the Software
// Licensing Service's fixed identifier for Windows itself, filtering out
// Office or any other licensed product that might also be installed.
func readActivationStatus() (string, error) {
	var products []win32SoftwareLicensingProduct
	const q = "SELECT LicenseStatus FROM SoftwareLicensingProduct " +
		"WHERE ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL"
	if err := wmi.Query(q, &products); err != nil {
		return "", err
	}
	if len(products) == 0 {
		return "", tel.ErrEmptyOutput
	}
	return activationStatusName(products[0].LicenseStatus), nil
}
