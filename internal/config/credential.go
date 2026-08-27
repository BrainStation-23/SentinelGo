package config

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

// Credential protection at rest.
//
// config.json holds three secrets — access_token, refresh_token and
// agent_secret — and until this abstraction existed they were stored as
// plaintext JSON. (process_flow.md claimed they were "encrypted at rest via
// EncryptSensitiveData()"; no such function ever existed, which is arguably
// worse than the gap itself, because documentation describing a control that is
// not there stops anyone from noticing it is missing.)
//
// # What this does and does not defend against
//
// Filesystem permissions — 0600/0700 on Unix, an explicit SYSTEM+Administrators
// DACL on Windows (see secure_unix.go / secure_windows.go) — already stop other
// unprivileged local users from reading the file. What they cannot do is
// protect the file once it LEAVES the machine: a backup, a disk image, a
// support bundle or a copied config directory yields working fleet credentials
// on any other machine.
//
// Machine-bound protection is the answer to that specific problem, and it is
// the problem worth solving here. It is deliberately not a defence against a
// process already running with the agent's own privileges on the endpoint: such
// a process can ask the OS to unprotect the value exactly as the agent does.
// Nothing short of a hardware-held key changes that, and claiming otherwise
// would repeat the original mistake.
//
// # Platform support
//
// Windows uses DPAPI at machine scope; every other platform keeps filesystem
// permissions alone and says so. See docs/security/credential-storage.md, and
// newProtector in the per-platform files.
//
// No home-grown cryptography anywhere: a platform either has an OS-backed
// mechanism this code can call, or it is honestly reported as unprotected.

const (
	// protectedPrefix marks a stored value as protected rather than plaintext.
	//
	// A marker rather than a separate JSON field, so the wire shape of
	// config.json is unchanged and a value round-trips through any code that
	// treats it as an opaque string. Reading tolerates both forms, which is
	// what makes the migration invisible: an existing plaintext config keeps
	// working and is upgraded on the next save.
	protectedPrefix = "enc:"

	// protectorDPAPI identifies Windows DPAPI-protected values.
	protectorDPAPI = "dpapi"

	// protectedFormatVersion allows the encoding to change later without
	// mistaking an old value for a corrupt one.
	protectedFormatVersion = "v1"
)

// CredentialProtection selects how secrets are stored at rest.
const (
	// CredentialProtectionAuto uses the best mechanism the platform offers, and
	// falls back to filesystem permissions where there is none. This is the
	// default.
	CredentialProtectionAuto = "auto"
	// CredentialProtectionOff stores secrets as plaintext JSON, as before.
	//
	// It exists for one real operational reason: a binary older than this
	// change cannot read a protected value, so a fleet that may need to roll
	// back to such a version can stage the change by leaving protection off
	// until the rollback window closes. See the rollback section of
	// docs/security/credential-storage.md.
	CredentialProtectionOff = "off"
)

// protector protects and unprotects a single secret value.
//
// Implementations must be symmetric on the same machine and must not invent
// their own cryptography — each one wraps an OS-provided facility.
type protector interface {
	// Name is the mechanism identifier stored in the value's marker.
	Name() string
	// Protect encodes plaintext into the opaque body of a marked value.
	Protect(plaintext string) (string, error)
	// Unprotect reverses Protect for a body this mechanism produced.
	Unprotect(body string) (string, error)
}

// isProtected reports whether v carries the protection marker.
func isProtected(v string) bool { return strings.HasPrefix(v, protectedPrefix) }

// wrap builds the stored form: "enc:<mechanism>:<version>:<body>".
func wrap(mechanism, body string) string {
	return protectedPrefix + mechanism + ":" + protectedFormatVersion + ":" + body
}

// unwrap splits a stored value into its mechanism, version and body.
func unwrap(v string) (mechanism, version, body string, ok bool) {
	if !isProtected(v) {
		return "", "", "", false
	}
	parts := strings.SplitN(strings.TrimPrefix(v, protectedPrefix), ":", 3)
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}

// protectValue returns the stored form of a secret.
//
// A value that is already protected is returned untouched, so saving a config
// that was loaded from disk without ever touching its tokens cannot double-wrap
// them. An empty value stays empty: protecting "" would turn "this agent has
// not registered yet" into an opaque blob that reads as a credential.
func protectValue(mode, plaintext string) string {
	if plaintext == "" || isProtected(plaintext) {
		return plaintext
	}
	if mode == CredentialProtectionOff {
		return plaintext
	}

	p := newProtector()
	if p == nil {
		return plaintext
	}

	body, err := p.Protect(plaintext)
	if err != nil {
		// Never fail the save: a config that cannot be written is a worse
		// outcome than one written with the protection this platform had
		// before. The failure is logged without the value.
		log.Printf("[config] credential protection unavailable (%s), storing with "+
			"filesystem permissions only: %v", p.Name(), err)
		return plaintext
	}
	return wrap(p.Name(), body)
}

// unprotectValue returns the plaintext of a stored value.
//
// Plaintext input passes through unchanged — that is the whole backward
// compatibility story, and it is why an agent upgrading onto this code keeps
// its registration instead of re-registering.
//
// A protected value that cannot be unprotected returns an error rather than an
// empty string. Silently yielding "" would send the agent down the
// re-registration path with an empty secret, turning a recoverable local
// problem (config restored onto different hardware) into a lost enrolment.
func unprotectValue(v string) (string, error) {
	mechanism, version, body, ok := unwrap(v)
	if !ok {
		return v, nil
	}
	if version != protectedFormatVersion {
		return "", fmt.Errorf("credential stored in unsupported format version %q", version)
	}

	p := newProtector()
	if p == nil || p.Name() != mechanism {
		return "", fmt.Errorf("credential was protected with %q, which this build "+
			"cannot read on this platform", mechanism)
	}

	plaintext, err := p.Unprotect(body)
	if err != nil {
		return "", fmt.Errorf("unprotect %s credential: %w", mechanism, err)
	}
	return plaintext, nil
}

// GetCredentialProtection returns the configured mode, defaulting to auto.
func (c *Config) GetCredentialProtection() string {
	if c.CredentialProtection == CredentialProtectionOff {
		return CredentialProtectionOff
	}
	return CredentialProtectionAuto
}

// CredentialProtectionMechanism names the mechanism in force on this endpoint,
// for diagnostics. It never returns a value derived from a secret.
func (c *Config) CredentialProtectionMechanism() string {
	if c.GetCredentialProtection() == CredentialProtectionOff {
		return "none (disabled by config)"
	}
	p := newProtector()
	if p == nil {
		return "none (filesystem permissions only on this platform)"
	}
	return p.Name()
}

// marshalProtected serialises c for storage, with its three credentials in
// protected form.
//
// # Why it works on the serialised form rather than on a struct
//
// Two approaches are ruled out, both for concrete reasons:
//
//   - Copying the struct (`clone := *c`) copies Config's `sync.Mutex` along
//     with everything else. `go vet` rejects it, correctly: SaveAtomic holds
//     that lock while saving, so the copy would capture a locked mutex.
//   - Swapping the fields in place and restoring them afterwards races. Several
//     call sites read `cfg.AccessToken` directly without taking the token lock
//     (the scheduler's refresh check, the audit-log uploader, the auth service),
//     so a concurrent reader could observe ciphertext and send it as a bearer
//     token — the exact failure this whole design avoids.
//
// Marshalling first and replacing three values in the decoded field map has
// neither problem: the live config is never touched and no lock is copied.
//
// One visible consequence: Go marshals maps with sorted keys, so a saved
// config.json has its keys in alphabetical order. Every key and value is
// preserved exactly; only the ordering differs from the input file.
func (c *Config) marshalProtected() ([]byte, error) {
	// #nosec G117 - Config includes AccessToken for persistence, saved with secure permissions
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}

	mode := c.GetCredentialProtection()
	for key, plaintext := range map[string]string{
		"access_token":  c.AccessToken,
		"refresh_token": c.RefreshToken,
		"agent_secret":  c.AgentSecret,
	} {
		if _, present := fields[key]; !present {
			// The field was omitted by its struct tag; nothing to protect.
			continue
		}
		encoded, err := json.Marshal(protectValue(mode, plaintext))
		if err != nil {
			return nil, err
		}
		fields[key] = encoded
	}

	return json.MarshalIndent(fields, "", "  ")
}

// unprotectSecrets converts this config's secrets from stored form to plaintext
// in place, immediately after it is read from disk.
//
// Errors name the field and nothing else. A credential that cannot be read is
// reported once, loudly, and left empty so the agent's existing "not
// authenticated" handling takes over rather than a token-shaped blob being sent
// to the backend.
func (c *Config) unprotectSecrets() error {
	var failed []string

	for _, f := range []struct {
		name string
		ptr  *string
	}{
		{"access_token", &c.AccessToken},
		{"refresh_token", &c.RefreshToken},
		{"agent_secret", &c.AgentSecret},
	} {
		plaintext, err := unprotectValue(*f.ptr)
		if err != nil {
			// The error text is from unprotectValue and is deliberately free of
			// the value; only the field name is added.
			log.Printf("[config] cannot read protected %s: %v", f.name, err)
			failed = append(failed, f.name)
			*f.ptr = ""
			continue
		}
		*f.ptr = plaintext
	}

	if len(failed) > 0 {
		return fmt.Errorf("could not unprotect stored credentials (%s); "+
			"this normally means config.json was copied from another machine, "+
			"which machine-bound protection is designed to prevent",
			strings.Join(failed, ", "))
	}
	return nil
}
