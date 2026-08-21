package encryption

import (
	"encoding/json"
	"strings"
)

// This file holds every platform's parsing as pure functions with no build
// tag, so it is unit tested on every host regardless of GOOS.

// ── Windows: Get-BitLockerVolume ────────────────────────────────────────────

type windowsVolumeRow struct {
	MountPoint           string   `json:"MountPoint"`
	ProtectionStatus     string   `json:"ProtectionStatus"`
	EncryptionPercentage *float64 `json:"EncryptionPercentage"`
	KeyProtectorTypes    []string `json:"KeyProtectorTypes"`
}

// parseWindowsVolumes parses Get-BitLockerVolume's JSON. A single volume
// serializes as a bare object rather than a one-element array, the same
// ambiguity handled throughout this codebase's other PowerShell-JSON call
// sites.
func parseWindowsVolumes(output string) ([]windowsVolumeRow, error) {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil, nil
	}

	var rows []windowsVolumeRow
	if err := json.Unmarshal([]byte(output), &rows); err == nil {
		return rows, nil
	}

	var single windowsVolumeRow
	if err := json.Unmarshal([]byte(output), &single); err != nil {
		return nil, err
	}
	return []windowsVolumeRow{single}, nil
}

func (r windowsVolumeRow) toVolume() Volume {
	protection := "unknown"
	switch strings.ToLower(r.ProtectionStatus) {
	case "on":
		protection = "on"
	case "off":
		protection = "off"
	}

	encType := "none"
	if protection == "on" || len(r.KeyProtectorTypes) > 0 {
		encType = "bitlocker"
	}

	return Volume{
		DriveLetter:          r.MountPoint,
		EncryptionType:       encType,
		ProtectionStatus:     protection,
		EncryptionPercentage: r.EncryptionPercentage,
		KeyProtectorTypes:    r.KeyProtectorTypes,
	}
}

// ── Linux: lsblk (LUKS) ──────────────────────────────────────────────────────

// lsblkNode is one entry (possibly nested) from
// `lsblk -o NAME,FSTYPE,MOUNTPOINT --json`.
type lsblkNode struct {
	Name       string      `json:"name"`
	FSType     string      `json:"fstype"`
	MountPoint string      `json:"mountpoint"`
	Children   []lsblkNode `json:"children"`
}

type lsblkTree struct {
	BlockDevices []lsblkNode `json:"blockdevices"`
}

// parseLinuxLUKS walks the lsblk device tree for crypto_LUKS containers,
// reporting each with the mount point of its first mapped child that
// actually has one (the unlocked/mapped device, not the raw container,
// carries the mount point in lsblk's hierarchy).
func parseLinuxLUKS(output string) ([]Volume, error) {
	var tree lsblkTree
	if err := json.Unmarshal([]byte(output), &tree); err != nil {
		return nil, err
	}

	var volumes []Volume
	var walk func(nodes []lsblkNode)
	walk = func(nodes []lsblkNode) {
		for _, n := range nodes {
			if n.FSType == "crypto_LUKS" {
				volumes = append(volumes, Volume{
					MountPoint:       firstMountPoint(n.Children),
					EncryptionType:   "luks",
					ProtectionStatus: "on",
				})
			}
			walk(n.Children)
		}
	}
	walk(tree.BlockDevices)
	return volumes, nil
}

func firstMountPoint(nodes []lsblkNode) string {
	for _, n := range nodes {
		if n.MountPoint != "" {
			return n.MountPoint
		}
		if mp := firstMountPoint(n.Children); mp != "" {
			return mp
		}
	}
	return ""
}

// ── macOS: fdesetup ──────────────────────────────────────────────────────────

// parseFdesetupStatus interprets `fdesetup status` output, which reads
// "FileVault is On." or "FileVault is Off." (optionally with additional
// lines describing an in-progress conversion).
func parseFdesetupStatus(output string) string {
	lower := strings.ToLower(output)
	switch {
	case strings.Contains(lower, "filevault is on"):
		return "on"
	case strings.Contains(lower, "filevault is off"):
		return "off"
	default:
		return "unknown"
	}
}
