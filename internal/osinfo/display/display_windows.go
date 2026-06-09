//go:build windows

package display

import (
	"crypto/md5"
	"fmt"
	"strings"

	"github.com/yusufpapurcu/wmi"

	"sentinelgo/internal/osinfo/shared"
)

type wmiMonitorID struct {
	InstanceName      string
	ManufacturerName  []int32
	UserFriendlyName  []int32
	SerialNumberID    []int32
	YearOfManufacture int32
	Active            bool
}

type wmiMonitorConnectionParams struct {
	InstanceName          string
	VideoOutputTechnology uint32
	Active                bool
}

type win32VideoController struct {
	CurrentHorizontalResolution uint32
	CurrentVerticalResolution   uint32
	CurrentRefreshRate          uint32
}

func getDisplays() (displays []shared.Display) {
	defer func() {
		if r := recover(); r != nil {
			displays = nil
		}
	}()

	var monitors []wmiMonitorID
	if err := wmi.QueryNamespace("SELECT * FROM WmiMonitorID", &monitors, `root\wmi`); err != nil || len(monitors) == 0 {
		return nil
	}

	var connParams []wmiMonitorConnectionParams
	_ = wmi.QueryNamespace("SELECT * FROM WmiMonitorConnectionParams", &connParams, `root\wmi`)
	connByInstance := make(map[string]wmiMonitorConnectionParams, len(connParams))
	for _, c := range connParams {
		connByInstance[c.InstanceName] = c
	}

	var controllers []win32VideoController
	_ = wmi.Query(
		"SELECT CurrentHorizontalResolution, CurrentVerticalResolution, CurrentRefreshRate FROM Win32_VideoController",
		&controllers,
	)
	var refreshRate float64
	var activeResolution string
	for _, c := range controllers {
		if c.CurrentHorizontalResolution > 0 {
			refreshRate = float64(c.CurrentRefreshRate)
			activeResolution = formatResolution(c.CurrentHorizontalResolution, c.CurrentVerticalResolution)
			break
		}
	}

	displays = make([]shared.Display, 0, len(monitors))
	for i, m := range monitors {
		manufacturer := wmiByteArrayToString(m.ManufacturerName)
		model := wmiByteArrayToString(m.UserFriendlyName)
		serial := wmiByteArrayToString(m.SerialNumberID)

		if serial == "" || serial == "0" {
			serial = instanceSerial(m.InstanceName)
		}

		conn := connByInstance[m.InstanceName]
		connType := videoOutputTechToString(conn.VideoOutputTechnology)

		desc := model
		if desc == "" {
			if connType != "" && connType != "Unknown" {
				desc = connType
			} else {
				desc = fmt.Sprintf("Display %d", i+1)
			}
		}

		d := shared.Display{
			Description:    desc,
			Manufacturer:   manufacturer,
			Model:          model,
			SerialNumber:   serial,
			Year:           int(m.YearOfManufacture),
			RefreshRate:    refreshRate,
			ConnectionType: connType,
		}
		if model != "" {
			if size := shared.ParseDisplaySizeFromName(model); size > 0 {
				d.Size = size
			}
		}
		d.Resolution = activeResolution
		displays = append(displays, d)
	}
	return displays
}

// formatResolution returns "WxH" or empty string if either dimension is zero.
func formatResolution(width, height uint32) string {
	if width == 0 || height == 0 {
		return ""
	}
	return fmt.Sprintf("%dx%d", width, height)
}

// wmiByteArrayToString converts a WMI null-terminated int32 array (COM returns VT_I4
// elements for WmiMonitorID byte arrays) to a trimmed Go string.
func wmiByteArrayToString(b []int32) string {
	var sb strings.Builder
	for _, c := range b {
		if c == 0 {
			break
		}
		sb.WriteByte(byte(c))
	}
	return strings.TrimSpace(sb.String())
}

// instanceSerial derives a stable 16-char serial from the WMI InstanceName
// when the monitor does not report one.
func instanceSerial(instanceName string) string {
	h := md5.Sum([]byte(instanceName))
	s := fmt.Sprintf("%X", h)
	if len(s) > 16 {
		s = s[:16]
	}
	return s
}

// videoOutputTechToString maps WmiMonitorConnectionParams.VideoOutputTechnology
// to a human-readable string. Values follow the D3DKMDT_VIDEO_OUTPUT_TECHNOLOGY enum.
func videoOutputTechToString(tech uint32) string {
	switch tech {
	case 0xFFFFFFFE: // -2 as int32 — Uninitialized
		return "Uninitialized"
	case 0xFFFFFFFF: // -1 as int32 — Other
		return "Other"
	case 0:
		return "VGA"
	case 1:
		return "S-Video"
	case 2:
		return "Composite Video"
	case 3:
		return "Component Video"
	case 4:
		return "DVI"
	case 5:
		return "HDMI"
	case 6:
		return "LVDS"
	case 8:
		return "D-Jpn"
	case 9:
		return "SDI"
	case 10:
		return "DisplayPort"
	case 11:
		return "DisplayPort Embedded"
	case 12:
		return "UDI External"
	case 13:
		return "UDI Embedded"
	case 14:
		return "SDTV Dongle"
	case 15:
		return "Miracast"
	case 0x80000000: // internal panel (laptops, all-in-ones)
		return "Internal"
	default:
		return "Unknown"
	}
}
