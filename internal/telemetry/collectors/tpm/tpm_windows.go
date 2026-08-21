//go:build windows

package tpm

import (
	"context"

	"sentinelgo/internal/osinfo/shared"
	tel "sentinelgo/internal/telemetry"
)

// tpmQuery projects only the four properties the payload reports.
//
// $ErrorActionPreference plus the try/catch is load-bearing: Get-CimInstance
// against a namespace that does not exist (which is what a machine with no TPM
// looks like) raises a non-terminating error and still exits 0, so without
// forcing it terminating the collector would read empty stdout as a successful
// "no TPM" on a machine whose TPM it simply failed to query. The same trap the
// encryption collector documents for Get-BitLockerVolume.
const tpmQuery = `$ErrorActionPreference = 'Stop'
try {
	Get-CimInstance -Namespace root/CIMV2/Security/MicrosoftTpm -ClassName Win32_Tpm |
		Select-Object IsEnabled_InitialValue,IsActivated_InitialValue,SpecVersion,ManufacturerIdTxt |
		ConvertTo-Json -Compress
} catch {
	exit 1
}`

const windowsSource = "powershell:Win32_Tpm"

// platformProbe queries Win32_Tpm once and derives both the capability and the
// payload from the same answer.
func platformProbe(ctx context.Context) probe {
	out, err := shared.RunCommandContext(ctx, "powershell", "-NoProfile", "-Command", tpmQuery)
	if err != nil {
		// The namespace is absent or the query was refused. Both mean the agent
		// could not establish TPM state; neither proves there is no chip, so
		// this is CapUnsupported rather than CapNotPresent.
		return probe{
			capability: tel.CapUnsupported,
			signal: signal{
				Source:   windowsSource,
				Warnings: []string{"Win32_Tpm query did not return a result"},
			},
		}
	}

	raw, ok := parseWindowsTPM(out)
	if !ok {
		// An empty, well-formed response is Windows saying there is no TPM
		// instance to describe.
		return probe{
			capability: tel.CapNotPresent,
			signal:     signal{Payload: Payload{Present: false}, Source: windowsSource},
		}
	}

	payload := Payload{
		Present:      true,
		Version:      specVersion(raw.SpecVersion),
		Manufacturer: raw.Manufacturer,
	}
	if raw.IsEnabled != nil {
		enabled := *raw.IsEnabled
		// A TPM that is enabled but not activated cannot be used, so both flags
		// have to hold before the payload claims it is usable.
		if raw.IsActivated != nil {
			enabled = enabled && *raw.IsActivated
		}
		payload.Enabled = &enabled
	}

	return probe{
		capability: tel.CapSupported,
		signal:     signal{Payload: payload, Source: windowsSource},
	}
}
