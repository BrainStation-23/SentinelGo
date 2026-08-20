package physicaldisks

import (
	"encoding/json"
	"strconv"
	"strings"
)

// This file holds every platform's parsing as pure functions with no build
// tag, so it is unit tested on every host regardless of GOOS — the pattern
// used throughout the other C1–C3 collectors.

// ── normalisation ────────────────────────────────────────────────────────────

// normalizeMediaType maps a platform-reported media type string to a stable
// "ssd"/"hdd"/"unspecified" value.
func normalizeMediaType(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "ssd", "solid state drive", "solid state media":
		return "ssd"
	case "hdd", "hard disk drive":
		return "hdd"
	default:
		return "unspecified"
	}
}

// normalizeBusType maps a platform-reported transport string to a stable,
// lowercase value.
func normalizeBusType(raw string) string {
	t := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case t == "":
		return ""
	case strings.Contains(t, "nvme"):
		return "nvme"
	case strings.Contains(t, "sata"):
		return "sata"
	case strings.Contains(t, "usb"):
		return "usb"
	case strings.Contains(t, "sas"):
		return "sas"
	case strings.Contains(t, "scsi"):
		return "scsi"
	case strings.Contains(t, "ata") || strings.Contains(t, "ide"):
		return "ata"
	case strings.Contains(t, "raid"):
		return "raid"
	default:
		return t
	}
}

// ── Windows: Get-PhysicalDisk + Get-StorageReliabilityCounter ──────────────

// windowsDiskRow is one row of the combined PowerShell JSON this collector
// requests: disk identity/health from Get-PhysicalDisk joined with the
// matching Get-StorageReliabilityCounter reading.
type windowsDiskRow struct {
	ID           string   `json:"Id"`
	Model        string   `json:"Model"`
	Serial       string   `json:"Serial"`
	Size         uint64   `json:"Size"`
	MediaType    string   `json:"MediaType"`
	BusType      string   `json:"BusType"`
	Health       string   `json:"Health"`
	Temperature  *float64 `json:"Temperature"`
	PowerOnHours *uint64  `json:"PowerOnHours"`
	Wear         *float64 `json:"Wear"`
	SmartHealthy *bool    `json:"SmartHealthy"`
}

// parseWindowsDisks parses the combined PowerShell script's JSON. A single
// disk serializes as a bare object rather than a one-element array, so both
// shapes are tried — the same ambiguity internal/osinfo/system/system_windows.go
// already handles for Win32_BIOS.
func parseWindowsDisks(output string) ([]windowsDiskRow, error) {
	output = strings.TrimSpace(output)
	if output == "" {
		return nil, nil
	}

	var rows []windowsDiskRow
	if err := json.Unmarshal([]byte(output), &rows); err == nil {
		return rows, nil
	}

	var single windowsDiskRow
	if err := json.Unmarshal([]byte(output), &single); err != nil {
		return nil, err
	}
	return []windowsDiskRow{single}, nil
}

func (r windowsDiskRow) toDisk() Disk {
	d := Disk{
		ID:           r.ID,
		Model:        strings.TrimSpace(r.Model),
		SerialNumber: strings.TrimSpace(r.Serial),
		SizeBytes:    r.Size,
		MediaType:    normalizeMediaType(r.MediaType),
		BusType:      normalizeBusType(r.BusType),
		HealthStatus: r.Health,
	}
	if r.Temperature != nil || r.PowerOnHours != nil || r.Wear != nil || r.SmartHealthy != nil {
		d.SMART = &SMART{
			Healthy:            r.SmartHealthy,
			TemperatureCelsius: r.Temperature,
			PowerOnHours:       r.PowerOnHours,
			WearPercentage:     r.Wear,
		}
	}
	return d
}

// ── Linux: lsblk + smartctl ─────────────────────────────────────────────────

// lsblkOutput is `lsblk --json -d -b -o NAME,TYPE,MODEL,SERIAL,SIZE,ROTA,TRAN`.
// SIZE and ROTA are numbers on recent util-linux but strings on some older
// versions, so they are decoded via flexibleString/flexibleUint rather than a
// fixed Go type.
type lsblkOutput struct {
	BlockDevices []lsblkDevice `json:"blockdevices"`
}

type lsblkDevice struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Model  string `json:"model"`
	Serial string `json:"serial"`
	Size   any    `json:"size"`
	Rota   any    `json:"rota"`
	Tran   string `json:"tran"`
}

func parseLsblkDisks(output string) ([]lsblkDevice, error) {
	var out lsblkOutput
	if err := json.Unmarshal([]byte(output), &out); err != nil {
		return nil, err
	}
	var disks []lsblkDevice
	for _, d := range out.BlockDevices {
		if d.Type == "disk" {
			disks = append(disks, d)
		}
	}
	return disks, nil
}

func (d lsblkDevice) toDisk() Disk {
	mediaType := "unspecified"
	if rota, ok := flexibleUint(d.Rota); ok {
		if rota == 0 {
			mediaType = "ssd"
		} else {
			mediaType = "hdd"
		}
	}
	size, _ := flexibleUint(d.Size)
	return Disk{
		ID:           d.Name,
		Model:        strings.TrimSpace(d.Model),
		SerialNumber: strings.TrimSpace(d.Serial),
		SizeBytes:    size,
		MediaType:    mediaType,
		BusType:      normalizeBusType(d.Tran),
	}
}

// flexibleUint reads a uint64 out of a JSON value that may have decoded as
// either a float64 (number) or a string, tolerating the lsblk version
// difference noted above.
func flexibleUint(v any) (uint64, bool) {
	switch t := v.(type) {
	case float64:
		if t < 0 {
			return 0, false
		}
		return uint64(t), true
	case string:
		n, err := strconv.ParseUint(strings.TrimSpace(t), 10, 64)
		if err != nil {
			return 0, false
		}
		return n, true
	default:
		return 0, false
	}
}

// smartctlResult is the subset of `smartctl --json=c -a <dev>` this collector
// reads. Letting smartctl itself decode the ATA attribute table — rather than
// this collector hand-parsing the raw MSStorageDriver_FailurePredictData byte
// blob — is the whole point: the risky offset arithmetic already happened
// inside smartctl, a tool whose only job is getting it right.
type smartctlResult struct {
	SmartStatus *struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature *struct {
		Current float64 `json:"current"`
	} `json:"temperature"`
	PowerOnTime *struct {
		Hours uint64 `json:"hours"`
	} `json:"power_on_time"`
	// NvmePercentageUsed is smartctl's own NVMe wear indicator — no ATA
	// attribute table involved for NVMe drives at all.
	NvmePercentageUsed *float64 `json:"nvme_percentage_used"`
	AtaSmartAttributes *struct {
		Table []struct {
			ID    int `json:"id"`
			Value int `json:"value"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
}

func parseSmartctlJSON(output string) (*smartctlResult, error) {
	var r smartctlResult
	if err := json.Unmarshal([]byte(output), &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// smartFromSmartctl extracts a SMART summary from a parsed smartctl result.
// Wear percentage prefers the direct NVMe indicator; failing that, it reads
// the normalized VALUE of ATA attribute 177 (SSD wear-leveling count) or 233
// (media wearout indicator), both of which smartctl reports as "percentage of
// life remaining" — so wear = 100 - value.
func smartFromSmartctl(r *smartctlResult) *SMART {
	if r == nil {
		return nil
	}
	s := &SMART{}
	hasData := false

	if r.SmartStatus != nil {
		passed := r.SmartStatus.Passed
		s.Healthy = &passed
		hasData = true
	}
	if r.Temperature != nil {
		temp := r.Temperature.Current
		s.TemperatureCelsius = &temp
		hasData = true
	}
	if r.PowerOnTime != nil {
		hours := r.PowerOnTime.Hours
		s.PowerOnHours = &hours
		hasData = true
	}

	switch {
	case r.NvmePercentageUsed != nil:
		wear := *r.NvmePercentageUsed
		s.WearPercentage = &wear
		hasData = true
	case r.AtaSmartAttributes != nil:
		for _, attr := range r.AtaSmartAttributes.Table {
			if attr.ID == 177 || attr.ID == 233 {
				wear := 100 - float64(attr.Value)
				s.WearPercentage = &wear
				hasData = true
				break
			}
		}
	}

	if !hasData {
		return nil
	}
	return s
}

// ── macOS: diskutil ──────────────────────────────────────────────────────────

// parseDiskutilListPhysical extracts physical disk device identifiers
// ("disk0", "disk2", ...) from `diskutil list` output, skipping synthesized
// APFS containers (which are not physical devices).
func parseDiskutilListPhysical(output string) []string {
	var ids []string
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "/dev/disk") {
			continue
		}
		if !strings.Contains(line, "physical)") {
			continue
		}
		rest := strings.TrimPrefix(line, "/dev/")
		idx := strings.Index(rest, " ")
		if idx < 0 {
			continue
		}
		ids = append(ids, rest[:idx])
	}
	return ids
}

// parseDiskutilInfo parses `diskutil info <dev>` into a lowercase-keyed map,
// the same right-aligned "Key:   Value" style already handled for Windows'
// dsregcmd in the directory collector.
func parseDiskutilInfo(output string) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(output, "\n") {
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		val := strings.TrimSpace(line[idx+1:])
		if key == "" || val == "" {
			continue
		}
		out[key] = val
	}
	return out
}

// parseDarwinDiskSizeBytes extracts the exact byte count from diskutil's
// "Disk Size" line, formatted like "500.3 GB (500277790720 Bytes) (exactly
// 977105264 512-Byte-Units)" — the parenthesized exact byte figure, not the
// rounded human value before it.
func parseDarwinDiskSizeBytes(diskSize string) uint64 {
	idx := strings.Index(diskSize, "(")
	if idx < 0 {
		return 0
	}
	rest := diskSize[idx+1:]
	end := strings.Index(rest, " Bytes")
	if end < 0 {
		return 0
	}
	n, err := strconv.ParseUint(strings.TrimSpace(rest[:end]), 10, 64)
	if err != nil {
		return 0
	}
	return n
}
