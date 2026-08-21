package tpm

import (
	"encoding/json"
	"strings"
)

// windowsTPM is the shape of the Win32_Tpm projection this collector requests.
//
// IsEnabled_InitialValue is a pointer so an absent field stays distinguishable
// from a present false. Reporting "TPM disabled" because a property was missing
// would be a fabricated security finding.
type windowsTPM struct {
	IsEnabled    *bool  `json:"IsEnabled_InitialValue"`
	IsActivated  *bool  `json:"IsActivated_InitialValue"`
	SpecVersion  string `json:"SpecVersion"`
	Manufacturer string `json:"ManufacturerIdTxt"`
}

// parseWindowsTPM decodes the ConvertTo-Json output of the Win32_Tpm query.
//
// PowerShell emits a bare object for one instance and an array for several; a
// machine has at most one TPM, but the array form is handled so a future
// multi-instance response does not silently parse as nothing.
func parseWindowsTPM(output string) (windowsTPM, bool) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return windowsTPM{}, false
	}

	var single windowsTPM
	if err := json.Unmarshal([]byte(trimmed), &single); err == nil {
		return single, true
	}

	var many []windowsTPM
	if err := json.Unmarshal([]byte(trimmed), &many); err == nil && len(many) > 0 {
		return many[0], true
	}
	return windowsTPM{}, false
}

// specVersion normalises Win32_Tpm's SpecVersion, which is a comma-separated
// list like "2.0, 0, 1.38" whose first element is the spec revision.
func specVersion(raw string) string {
	first, _, _ := strings.Cut(raw, ",")
	return strings.TrimSpace(first)
}

// linuxVersion turns the contents of tpm_version_major ("1" or "2") into the
// spec version string the payload reports.
func linuxVersion(major string) string {
	switch strings.TrimSpace(major) {
	case "2":
		return "2.0"
	case "1":
		return "1.2"
	default:
		return ""
	}
}
