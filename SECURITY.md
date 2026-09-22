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
- The Supabase Edge Functions under `supabase/`
- The installation scripts under `installation-doc/`
- The build and release pipeline (`.github/workflows/`)

Out of scope:

- The Supabase platform itself (report those to [Supabase](https://supabase.com/security))
- GitHub infrastructure
- Third-party dependencies — report those to their respective maintainers; we will track the fix and update our dependency

---

## Security Architecture

SentinelGo runs as a privileged system service (systemd / launchd / Windows SCM) and communicates exclusively with a Supabase backend. The points below describe the security controls built into the agent.

### Authentication and credentials

- Every agent authenticates to the backend using a unique `agent_uuid` / `agent_secret` pair. These are never derived from hostnames or other guessable data.
- On successful login the agent receives a short-lived JWT. The JWT is automatically refreshed before expiry; the agent never relies on a single long-lived token.
- A circuit-breaker in `internal/auth/` limits the number of consecutive failed auth attempts and introduces back-off to resist credential-stuffing.
- Credentials are stored on disk using the OS credential store where available (`internal/config/secure_unix.go`, `internal/config/secure_windows.go`). The config file is written with restrictive permissions.

### Transport security

- All communication with Supabase and GitHub uses HTTPS. Plain HTTP is not used and there is no downgrade path.
- The shared HTTP client (`internal/httpx/`) enforces timeouts on every outbound request.

### Task execution (script runner)

- Script payloads are downloaded exclusively from a Supabase Storage bucket that is protected by Row Level Security. The agent uses its authenticated JWT for every download; unauthenticated requests are rejected by the backend.
- The task runner (`internal/service/task/`) does not evaluate or interpolate the script path — it downloads to a temporary file and executes it with the OS shell.
- Execution results (exit code, stdout, stderr) are uploaded back to the backend. The sanitize package (`internal/sanitize/`) redacts PII and credential-like patterns from outputs before they leave the machine.

### Automatic updates

- Release binaries are cross-compiled with `CGO_ENABLED=0` (fully static, no C runtime dependency).
- Each release ships a `SHA256SUMS` file. The signing script (`scripts/sign`) generates these checksums at release time. **Verifying the checksum before running a downloaded binary is strongly recommended** — see `installation-doc/INSTALLATION.md`.
- The updater (`internal/updater/`) fetches the latest release tag from the GitHub Releases API over HTTPS, selects the matching asset by exact name, and performs an atomic binary replace on disk.
- Binary signature verification (cryptographic signing beyond SHA-256) is a planned enhancement.

### Audit log collection

- The audit log collector (`internal/auditlogs/collector/`) reads from OS-native event sources (Windows Event Log, Linux journald, macOS unified log) using read-only APIs. It does not modify system logs.
- Events are queued in a local SQLite database (`internal/auditlogstore/`) before upload. The queue provides at-least-once delivery without losing events across restarts.

### Process isolation

- The lockfile module (`internal/lockfile/`) enforces single-instance execution. The lock key includes the agent UUID and binary version, so an in-place upgrade does not block the new process from starting.
- The agent drops no privileges on startup; it runs at the level required by the service manager. Avoid running as `root` or `SYSTEM` unless the installation guide specifically requires it for a feature on your platform.

---

## CI/CD Security Controls

Every pull request and release runs:

| Check | Tool | Gate |
|-------|------|------|
| Dependency vulnerability scan | `govulncheck` | Build fails on known vulnerabilities |
| Filesystem/secret/misconfiguration scan | Trivy (CRITICAL + HIGH) | Build fails |
| Static analysis | Gosec | Findings uploaded to GitHub Security tab (advisory only) |
| Module integrity | `go mod verify` | Build fails on tampered modules |
| CGO enforcement | Custom grep | Build fails if `import "C"` is introduced |
| Lint (all three OSes) | golangci-lint | Build fails |

Release binaries are produced only after the full CI pipeline passes. No binary is attached to a GitHub Release unless all gates are green.

---

## Known Limitations

The following gaps are acknowledged and on the roadmap:

1. **Cryptographic binary signing** — Release binaries are currently protected by SHA-256 checksums only. A proper code-signing scheme (e.g., sigstore/cosign) is planned.
2. **Update rollback** — There is no automated rollback if the newly applied binary fails to start. Manual recovery requires re-downloading a previous release.
3. **No mTLS** — The agent authenticates to Supabase via JWT, not mutual TLS. This is an inherent constraint of the Supabase Edge Function API.

---

## Acknowledgements

We thank everyone who has responsibly disclosed security issues to us. Contributors will be listed here with their consent.
