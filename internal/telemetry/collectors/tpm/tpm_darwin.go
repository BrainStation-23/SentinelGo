//go:build darwin

package tpm

import (
	"context"

	tel "sentinelgo/internal/telemetry"
)

// platformProbe reports CapNotPresent unconditionally.
//
// No Mac has a TPM. Apple ships the Secure Enclave, which is different hardware
// with a different attestation model and a different API, so mapping it onto a
// TPM payload would put a fabricated answer on the wire — precisely what the
// capability model exists to prevent. CapNotPresent is the truthful result:
// there is no TPM here, nothing is broken, and no action is possible.
//
// Secure Enclave state, if it is wanted later, belongs in its own section with
// its own capability key rather than borrowed into this one.
func platformProbe(context.Context) probe {
	return probe{
		capability: tel.CapNotPresent,
		signal: signal{
			Payload: Payload{Present: false},
			Source:  "static:darwin-has-no-tpm",
		},
	}
}
