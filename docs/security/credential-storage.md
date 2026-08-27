# Credential Storage at Rest

How SentinelGo stores `access_token`, `refresh_token` and `agent_secret`, what
that does and does not protect, and what happens on upgrade and rollback.

**Nothing in this document describes a control that is not implemented.** The
gap this work closes was created by the opposite: `process_flow.md` claimed
tokens were "encrypted at rest via `EncryptSensitiveData()`", a function that
never existed in this repository. A documented control that is absent is worse
than a documented gap, because it stops anyone from noticing.

---

## 1. What is stored, and where

| Path | Contents |
|---|---|
| `C:\sentinelgo\.sentinelgo\config.json` (Windows) | agent configuration, including the three credentials |
| `/opt/sentinelgo/.sentinelgo/config.json` (Linux/macOS) | same |

`agent_secret` is the long-lived credential used to obtain a session from the
`agent-login` edge function. `access_token` and `refresh_token` are the session
that follows. Possession of `agent_secret` alone is enough to impersonate the
endpoint to the backend.

## 2. Controls in force

| Control | Windows | Linux | macOS | Implementation |
|---|---|---|---|---|
| Directory permissions | SYSTEM + Administrators DACL | `0700` | `0700` | `internal/config/secure_windows.go`, `secure_unix.go` |
| File permissions | SYSTEM + Administrators DACL | `0600` | `0600` | same |
| Atomic write (no torn config) | ✅ | ✅ | ✅ | `Config.SaveAtomic` |
| **Encryption at rest** | ✅ **DPAPI, machine scope** | ❌ **not implemented** | ❌ **not implemented** | `internal/config/credential*.go` |

`os.Chmod` only toggles the read-only bit on Windows, which is why a real DACL is
set there instead.

## 3. The threat this addresses

Filesystem permissions already stop other unprivileged local users from reading
the file. What they cannot do is protect the credentials once the file **leaves
the endpoint**: a backup, a disk image, a support bundle, or a copied config
directory yields working fleet credentials on any other machine.

Machine-bound protection is the answer to that specific problem. On Windows,
DPAPI at machine scope makes the stored blob meaningless anywhere except the
machine that wrote it.

**What it deliberately does not defend against:** a process already running with
the agent's privileges on the endpoint. Such a process can ask the OS to
unprotect the value exactly as the agent does. Nothing short of a hardware-held
key changes that, and claiming otherwise would repeat the original mistake.

The two controls are complementary, not redundant:

- the **DACL** governs who on this machine may read the file;
- **DPAPI** governs whether the contents mean anything anywhere else.

## 4. Windows: DPAPI at machine scope

`CryptProtectData` / `CryptUnprotectData` with `CRYPTPROTECT_LOCAL_MACHINE`,
called through `golang.org/x/sys/windows` — pure syscalls, **no cgo**, so the
static cross-compiled build is unaffected.

Machine scope rather than user scope is **required for correctness**, not just
preferred. `config.json` is written by the installer, read by the service as
LocalSystem, and read again by the elevated CLI (`-status`, `-telemetry-health`)
running as an administrator. User-scope protection binds the blob to whichever
account wrote it, so the next reader — including the service itself after a
service-identity or gMSA change — would fail to decrypt it.

No additional entropy is passed. Entropy would have to be stored on the same
machine to be usable by the agent, so it would add a step for an attacker who
already has local access and nothing at all against the copied-file threat.

The unprotect path zeroes the plaintext buffer DPAPI allocates before freeing
it, so the credential is not left as residue in freed heap memory.

## 5. Linux and macOS: not implemented, and why

Both are **explicitly unprotected beyond filesystem permissions**.
`CredentialProtectionMechanism()` reports
`none (filesystem permissions only on this platform)` so nothing claims
otherwise.

**macOS.** The Keychain has no pure-Go binding. Reaching it means either cgo
against `Security.framework` — forbidden by `CLAUDE.md`, for reasons unrelated
to this feature — or shelling out to `/usr/bin/security`, whose
`add-generic-password` takes the secret as a **command-line argument** and so
exposes it in the process table to every user on the machine. Neither is
acceptable.

**Linux.** There is no single mechanism present on every target. The kernel
keyring is not persistent across reboots without a keyring daemon;
libsecret/D-Bus assumes a desktop session this service does not have; TPM
sealing needs a TPM and tooling many fleet images lack. A mechanism that works
on some hosts and silently does not on others produces a fleet where nobody can
say which endpoints are protected.

**No home-grown cryptography is used as a substitute.** Encrypting with a key
stored beside the ciphertext, on the same disk, readable by the same account,
protects against nothing while making the config *look* protected.

Closing these gaps properly is future work; see §9.

## 6. Storage format

A protected value keeps its JSON field and carries a marker:

```
"access_token": "enc:dpapi:v1:AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAA..."
```

`enc:` `<mechanism>` `:` `<format version>` `:` `<base64 body>`

A value **without** the marker is plaintext. That single rule is the entire
backward-compatibility story: reading tolerates both forms, so an existing
installation keeps working and is upgraded on its next save.

Only the three credentials are protected. `supabase_url`, `device_id`,
`agent_id`, intervals and feature flags stay readable so an operator can still
inspect and edit `config.json`.

## 7. Lifecycle

| Event | Behaviour |
|---|---|
| **First install** | Installer deploys a plaintext `config.json`. First save by the agent protects it. |
| **Registration** | Unchanged. `agent_secret` is protected on the save that persists it. |
| **Token refresh** (every 1m) | `SaveAtomic` writes protected values. The in-memory config keeps plaintext — a **copy** is protected for serialisation, so the next request still sends a real bearer token. |
| **Agent upgrade** (self-update or installer) | Only the binary is replaced; `config.json` is preserved. A plaintext config is read normally and protected on the next save. **No re-registration.** |
| **Uninstall / reinstall** | `install.bat` backs up `config.json` and restores it unless `CLEAN_INSTALL` is set. A protected config restored onto the **same** machine works. |
| **Restore onto different hardware** | Decryption fails **by design** — that is the threat being defended. The agent logs the failure, starts with empty credentials, and must be re-enrolled with a fresh `config.json`. |
| **Backup / disk image** | Credentials in the image are useless on any other machine. |

## 8. Upgrade and rollback

**Upgrade is safe and needs no action.** Plaintext is read, then protected on
the next save.

**Rollback to a binary older than this change is NOT transparent.** An older
binary does not understand the `enc:` marker and will read the literal string
`enc:dpapi:v1:...` as the credential. Authentication fails, and because
`agent_secret` is protected too, re-login fails as well — the endpoint cannot
recover on its own.

Three supported options, in order of preference:

1. **Restore the backed-up config.** `install.bat` copies `config.json` aside
   before every non-clean install; restoring that plaintext file returns the
   endpoint to a working state on the older binary.
2. **Stage the rollout with protection off.** Set
   `"credential_protection": "off"` in `config.json` while a rollback window is
   open. Credentials are stored exactly as before, under filesystem permissions
   alone, and any binary can read them. Remove the setting to enable protection
   once the window closes.
3. **Re-deploy `config.json`** with fresh credentials.

`"credential_protection"` accepts `"auto"` (default — use the best mechanism the
platform offers) and `"off"`. An unrecognised value resolves to `auto`: a typo
must not silently turn a security control off.

## 9. Known gaps

| Gap | Status |
|---|---|
| macOS Keychain integration | Not implemented — see §5 |
| Linux OS-backed secret storage | Not implemented — see §5 |
| Protection against a local process running as the agent's identity | Out of scope by design — see §3 |
| Rollback to a pre-protection binary | Requires a config restore — see §8 |

## 10. Verifying on an endpoint

```bash
# What protection is actually in force
sentinelgo -status

# Confirm the credentials are not readable in the file (Windows)
findstr /C:"enc:dpapi" C:\sentinelgo\.sentinelgo\config.json
```

Secrets are never written to the application log. Error messages about
unreadable credentials name the **field** only, never the value or the stored
body.
