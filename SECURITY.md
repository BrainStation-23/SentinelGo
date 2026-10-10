# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | ✅ |
| Previous release | ✅ (critical fixes only) |
| Older releases | ❌ |

Only the two most recent releases receive security fixes. If you are running an older version, upgrade before reporting.

## Reporting a Vulnerability

**Please do not file a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately using one of the following channels:

- **GitHub Private Vulnerability Reporting** — preferred. Open a draft security advisory at `Security → Report a vulnerability` in this repository.
- **Email** — if you cannot use GitHub's private reporting, email the maintainers directly. Find the contact address in the repository's GitHub profile.

Include as much detail as you can:

- A clear description of the vulnerability and the affected component
- Steps to reproduce or a proof-of-concept (a minimal reproducer is better than a full exploit)
- The potential impact and attack surface (e.g., local privilege escalation, credential exposure, remote code execution)
- The platform(s) and version(s) affected
- Any suggested mitigations if you have them

### Response timeline

| Milestone | Target |
|-----------|--------|
| Acknowledge receipt | 2 business days |
| Confirm or refute the report | 5 business days |
| Share a remediation plan | 10 business days |
| Release a fix (for confirmed critical/high findings) | 30 days |

We will keep you informed at each step. If a deadline cannot be met we will tell you why and give an updated estimate.

### Coordinated disclosure

We follow coordinated disclosure. We ask that you give us reasonable time to develop and ship a fix before any public disclosure. Once a fix is released we are happy to credit you in the release notes and in this file (if you wish).

---

## Scope

The following are in scope:

- The SentinelGo agent binary and all packages under `internal/` and `cmd/`
- The installation scripts under `installation-doc/`
- The build and release pipeline (`.github/workflows/`)

Out of scope:

- The Supabase platform itself (report those to [Supabase](https://supabase.com/security))
- GitHub infrastructure
- Third-party dependencies — report those to their respective maintainers; we will track the fix and update our dependency

---

## Security Architecture

SentinelGo runs as a privileged system service (systemd / launchd / Windows SCM) and communicates exclusively with a Supabase backend. The points below describe the security controls built into the agent. The threat model and the reasoning behind these controls are in the [assurance case](docs/assurance-case.md).

### What to expect

SentinelGo **is designed to protect**:

- the agent's credentials and the data it collects, in transit (HTTPS only) and at rest on the device (owner-only file permissions);
- the agent binary itself: updates are installed only if they are newer, match the published SHA-256 checksum and carry a valid Ed25519 signature;
- the device from the agent's own mistakes: input from the OS and the network is validated and fuzzed, external commands are run by absolute path, and task output is redacted before upload.

SentinelGo **does not protect against**:

- **A compromised backend.** The backend can send tasks that run scripts with the agent's privileges (root or SYSTEM). Anyone who controls your Supabase project or its service-role key controls every enrolled device. Protect the backend accordingly.
- **A local administrator or root user.** They can read the agent's config, including its credentials, and stop or replace the agent.
- **A compromised device.** SentinelGo reports a device's state; it is not an antivirus or EDR and does not prevent attacks on the device.

### Authentication and credentials

- Every agent authenticates to the backend using a unique `agent_uuid` / `agent_secret` pair. These are never derived from hostnames or other guessable data.
- On successful login the agent receives a short-lived JWT. The JWT is automatically refreshed before expiry; the agent never relies on a single long-lived token.
- A circuit breaker (`internal/resilience/`) stops repeated failing calls and backs off, so a misconfigured or rejected agent doesn't hammer the backend.
- The agent secret and tokens are stored in cleartext in `config.json`, protected by file permissions: mode `0600` in an owner-only `0700` directory on Linux and macOS (`internal/config/secure_unix.go`), and an explicit DACL allowing only SYSTEM, Administrators and the agent's account on Windows (`internal/config/secure_windows.go`).

### Transport security

- The agent only talks to the Supabase backend, over HTTPS. A `supabase_url` that isn't `https://` is rejected at startup, so there is no plaintext or downgrade path.
- TLS uses Go's `crypto/tls` defaults: TLS 1.2 or newer, certificate verification always on.
- The shared HTTP client (`internal/httpx/`) enforces timeouts on every outbound request.

### Task execution (script runner)

- Script payloads are downloaded exclusively from a Supabase Storage bucket that is protected by Row Level Security. The agent uses its authenticated JWT for every download; unauthenticated requests are rejected by the backend.
- The task runner (`internal/service/task/`) does not evaluate or interpolate the script path — it downloads to a temporary file and executes it with the OS shell. Scripts larger than 10 MiB are rejected.
- Scripts run with the agent's privileges. This is by design (they exist to administer the device), and it is why the backend must be trusted; see "What to expect" above.
- Execution results (exit code, stdout, stderr) are uploaded back to the backend. The sanitize package (`internal/sanitize/`) redacts PII and credential-like patterns from outputs before they leave the machine.

### Automatic updates

- Release binaries are cross-compiled with `CGO_ENABLED=0` (fully static, no C runtime dependency) and are reproducible; see [`RELEASE.md`](RELEASE.md).
- Every release binary and installer is signed with Ed25519 (`scripts/sign`), listed in `SHA256SUMS`, and has a GitHub build-provenance attestation.
- The updater (`internal/updater/`) asks the backend for the latest release through the `get_latest_agent_release` RPC and downloads the binary and its `.sig` from Supabase Storage. It installs the update only if:
  - the version is strictly newer than the running one (no downgrades),
  - the SHA-256 matches the release manifest, and
  - the Ed25519 signature verifies against the public key compiled into the agent (`internal/updater/pubkey.go`). A missing or invalid signature is a hard failure.
- The current binary is backed up first, the new one replaces it atomically, and a failed replace rolls back to the backup.
- The installers verify the binary against `SHA256SUMS` and refuse to install if the file is missing. See [`installation-doc/INSTALLATION.md`](installation-doc/INSTALLATION.md).

### Audit log collection

- The audit log collector (`internal/auditlogs/collector/`) reads from OS-native event sources (Windows Event Log, Linux journald, macOS unified log) using read-only APIs. It does not modify system logs.
- Events are queued in a local SQLite database (`internal/store/`) before upload. The queue provides at-least-once delivery without losing events across restarts.

### Process isolation

- The lockfile module (`internal/lockfile/`) enforces single-instance execution. The lock key includes the agent UUID and binary version, so an in-place upgrade does not block the new process from starting.
- The agent drops no privileges on startup; it runs at the level required by the service manager. Avoid running as `root` or `SYSTEM` unless the installation guide specifically requires it for a feature on your platform.

---

## CI/CD Security Controls

Every pull request and release runs:

| Check | Tool | Gate |
|-------|------|------|
| Static analysis | CodeQL | Merging to `main` is blocked on high-severity alerts |
| Static analysis | Semgrep | Required check |
| Static analysis and coverage | SonarCloud | Quality gate reported on every pull request |
| Static analysis | gosec | Findings uploaded to the GitHub Security tab (advisory only) |
| Secret scanning | GitGuardian | Required check |
| Dependency vulnerability scan | `govulncheck` | Build fails on known vulnerabilities |
| Filesystem/secret/misconfiguration scan | Trivy (CRITICAL + HIGH) | Build fails |
| Module integrity | `go mod verify` | Build fails on tampered modules |
| CGO enforcement | Custom grep | Build fails if `import "C"` is introduced |
| Lint (all three OSes) | golangci-lint | Build fails |
| Fuzzing | Go native fuzzing | Nightly, on every parser of untrusted input |

Release binaries are produced only after the full CI pipeline passes. No binary is attached to a GitHub Release unless all gates are green. The `main` branch only accepts changes through pull requests that pass the required checks, with no bypass for anyone.

---

## Known Limitations

The following gaps are acknowledged and tracked in the [roadmap](ROADMAP.md):

1. **Update rollback after a failed start** — A failed binary replace rolls back automatically, but if the new binary is installed and then fails to start, there is no automatic rollback. Recovery means reinstalling a previous release.
2. **Cleartext credentials on disk** — The agent secret and tokens are protected by file permissions, not encrypted with an OS keychain.
3. **No mTLS** — The agent authenticates to Supabase via JWT, not mutual TLS. This is an inherent constraint of the Supabase Edge Function API.

---

## Acknowledgements

We thank everyone who has responsibly disclosed security issues to us. Contributors will be listed here with their consent.
