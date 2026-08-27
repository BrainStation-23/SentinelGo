//go:build !windows

package config

// newProtector reports that this platform has no credential protection wired up
// yet, so secrets are stored as plaintext JSON under the filesystem permissions
// applied by secure_unix.go (0600 file, 0700 directory).
//
// Returning nil is the honest answer, and it is the reason this file contains
// no cryptography. The alternative — encrypting with a key stored beside the
// ciphertext, on the same disk, readable by the same account — protects against
// nothing while making the config look protected, and a security control that
// only appears to work is worse than a documented gap. That mistake has already
// been made once in this repository: process_flow.md claimed credentials were
// "encrypted at rest via EncryptSensitiveData()", a function that never existed.
//
// # What each platform would need
//
// macOS: the Keychain, which has no pure-Go binding. Reaching it means either
// cgo against Security.framework — forbidden by CLAUDE.md, and for good reasons
// that have nothing to do with this feature — or shelling out to /usr/bin/security,
// whose add-generic-password takes the secret as a command-line argument and so
// exposes it in the process table to every user on the machine. Neither is
// acceptable, so macOS is left explicitly unprotected rather than badly
// protected.
//
// Linux: there is no single mechanism present on every target. The kernel
// keyring is not persistent across reboots without a keyring daemon;
// libsecret/D-Bus assumes a desktop session this service does not have; TPM
// sealing needs a TPM and tooling that many fleet Linux images lack. A
// mechanism that works on some hosts and silently does not on others produces a
// fleet where nobody can say which endpoints are protected, which is its own
// problem.
//
// Both are tracked in docs/security/credential-storage.md. Until one is
// implemented, `CredentialProtectionMechanism()` reports "filesystem permissions
// only on this platform" so nothing anywhere claims a protection that is absent.
func newProtector() protector { return nil }
