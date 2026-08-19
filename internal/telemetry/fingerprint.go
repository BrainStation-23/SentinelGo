package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// SectionData maps a section name to the payload collected for it.
//
// This is a distinct named type rather than a bare map so that the boundary
// between "section content" and "envelope metadata" is explicit at every call
// site. Only section content may be fingerprinted.
type SectionData map[string]any

// SectionHashes maps a section name to the hex SHA-256 of its content.
type SectionHashes map[string]string

// Fingerprint hashes each section's payload independently.
//
// Per-section hashing is what allows a changed firewall state to be uploaded
// without also re-sending unchanged CPU, RAM, disk and peripheral data.
//
// Determinism note for collector authors: encoding/json sorts map keys and
// preserves struct field order, so those are stable. SLICES ARE NOT — a
// collector that returns processes or certificates in OS-enumeration order will
// produce a different hash every cycle and defeat reconciliation. Sort list
// payloads by a stable key before returning them.
//
// An error is returned if any value is envelope metadata (see errMetaInSection);
// that is a programming error, not a runtime condition.
func Fingerprint(data SectionData) (SectionHashes, error) {
	out := make(SectionHashes, len(data))
	for name, payload := range data {
		if err := guardNotMeta(name, payload); err != nil {
			return nil, err
		}
		h, err := HashSection(payload)
		if err != nil {
			return nil, fmt.Errorf("fingerprint section %q: %w", name, err)
		}
		out[name] = h
	}
	return out, nil
}

// HashSection returns the hex SHA-256 of payload's canonical JSON encoding.
func HashSection(payload any) (string, error) {
	buf, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:]), nil
}

// guardNotMeta rejects envelope metadata that was mistakenly placed in a
// section.
//
// This guard exists because it is the single failure mode that would silently
// disable the entire reconciliation design: CollectorResult and TelemetryHealth
// carry durations, timestamps and queue depths that differ on every cycle, so a
// section containing one of them would hash differently every time, mark itself
// changed forever, and quietly restore the full-payload-every-cycle behaviour
// this layer exists to avoid. Failing loudly is far better than failing
// expensively and invisibly.
func guardNotMeta(section string, payload any) error {
	switch payload.(type) {
	case Meta, *Meta,
		CollectorResult, *CollectorResult, []CollectorResult,
		TelemetryHealth, *TelemetryHealth,
		DomainHealth, *DomainHealth, []DomainHealth:
		return fmt.Errorf(
			"telemetry: section %q contains envelope metadata (%T); "+
				"metadata is volatile and must live in Envelope.Meta, never in a fingerprinted section",
			section, payload)
	default:
		return nil
	}
}

// Changed returns the names of sections whose hash differs from prev, plus any
// section present in cur but absent from prev. The result is sorted.
//
// Sections missing from cur are NOT reported: absence means "not collected this
// cycle", not "deleted". Treating them as changes would upload stale data.
func Changed(prev, cur SectionHashes) []string {
	var changed []string
	for name, h := range cur {
		if prev[name] != h {
			changed = append(changed, name)
		}
	}
	sort.Strings(changed)
	return changed
}
