package volumes

import (
	"encoding/json"
	"strconv"
	"strings"
)

// This file holds every platform's parsing as pure functions with no build
// tag, so it is unit tested on every host regardless of GOOS.

// ── Windows: Get-Volume ─────────────────────────────────────────────────────

type windowsVolumeRow struct {
	DriveLetter     string `json:"DriveLetter"`
	FileSystemLabel string `json:"FileSystemLabel"`
	FileSystem      string `json:"FileSystem"`
	Size            uint64 `json:"Size"`
	SizeRemaining   uint64 `json:"SizeRemaining"`
}

// parseWindowsVolumes parses Get-Volume's JSON. A single volume serializes as
// a bare object rather than a one-element array, the same ambiguity handled
// throughout this codebase's other PowerShell-JSON call sites.
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
	letter := strings.TrimSpace(r.DriveLetter)
	if letter != "" {
		letter += ":"
	}
	return Volume{
		DriveLetter: letter,
		Label:       strings.TrimSpace(r.FileSystemLabel),
		FileSystem:  r.FileSystem,
		SizeBytes:   r.Size,
		FreeBytes:   r.SizeRemaining,
	}
}

// ── Linux: df ────────────────────────────────────────────────────────────────

// parseLinuxDF parses `df --block-size=1 --output=target,fstype,size,avail`.
// Mount point is the first column, so it is read up to the point the
// remaining three whitespace-separated numeric/type fields begin — safe even
// for the rare mount point containing spaces, unlike splitting purely on
// whitespace.
func parseLinuxDF(output string) []Volume {
	lines := strings.Split(output, "\n")
	var volumes []Volume
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // header
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		fsType := fields[len(fields)-3]
		size, sizeOK := parseUint(fields[len(fields)-2])
		avail, availOK := parseUint(fields[len(fields)-1])
		if !sizeOK || !availOK {
			continue
		}
		mountPoint := strings.Join(fields[:len(fields)-3], " ")
		volumes = append(volumes, Volume{
			MountPoint: mountPoint,
			FileSystem: fsType,
			SizeBytes:  size,
			FreeBytes:  avail,
		})
	}
	return volumes
}

// ── macOS: df ────────────────────────────────────────────────────────────────

// parseDarwinDF parses `df -k` output. BSD df has no --output flag and its
// column count varies by macOS version (some add iused/ifree/%iused between
// Capacity and Mounted-on), so the LAST field ending in "%" (Capacity, or
// %iused when present — either way the last percentage column) is used as an
// anchor: everything after it is the mount point, everything from field[1]
// to that anchor is blocks/used/available/capacity in a stable order.
func parseDarwinDF(output string) []Volume {
	lines := strings.Split(output, "\n")
	var volumes []Volume
	for i, line := range lines {
		if i == 0 || strings.TrimSpace(line) == "" {
			continue // header
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		anchor := -1
		for idx := len(fields) - 1; idx >= 0; idx-- {
			if strings.HasSuffix(fields[idx], "%") {
				anchor = idx
				break
			}
		}
		if anchor < 0 || anchor+1 >= len(fields) {
			continue
		}

		blocks1024, blocksOK := parseUint(fields[1])
		avail1024, availOK := parseUint(fields[3])
		if !blocksOK || !availOK {
			continue
		}

		mountPoint := strings.Join(fields[anchor+1:], " ")
		volumes = append(volumes, Volume{
			MountPoint: mountPoint,
			SizeBytes:  blocks1024 * 1024,
			FreeBytes:  avail1024 * 1024,
		})
	}
	return volumes
}

func parseUint(s string) (uint64, bool) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}
