// Package detect scans text for sensitive data: secrets (the betterleaks
// ruleset, embedded as data), PII (Presidio-port recognizers with checksum
// validators) and admin-defined regex and keyword rules from the policy. It is
// pure and deterministic, does no I/O and runs inside the session helper.
//
// The detection engine is added in #259.
package detect
