# Security assurance case

This document argues why SentinelGo meets its security requirements. It covers
the threat model, the trust boundaries, how secure-design principles are
applied, and how common implementation weaknesses are countered. The
user-facing summary, including what SentinelGo does **not** protect against,
is in [`SECURITY.md`](../SECURITY.md#what-to-expect).

It reflects the code on `main`. When a change affects any claim here, update
this document in the same pull request.

## 1. What SentinelGo is

A single static Go binary that runs as a privileged service (root via systemd
or launchd, SYSTEM via the Windows service manager) on each managed device. It:

- collects hardware, software, network and security-posture data, and OS audit logs;
- sends them to the operator's Supabase backend over HTTPS;
- runs tasks the backend queues for it, including scripts;
- updates itself from releases the backend publishes.

## 2. Security requirements

| ID | Requirement |
|---|---|
| R1 | Only the operator's backend can receive the device's data or give the agent instructions. |
| R2 | Data and credentials are confidential and unmodified in transit. |
| R3 | The agent's credentials are readable only by privileged local accounts. |
| R4 | The agent only ever runs code built from this repository by its release pipeline, or scripts the backend sends. |
| R5 | Untrusted local input (files, logs and command output that unprivileged users can influence) cannot make the agent run code or crash. |
| R6 | Collected output is stripped of credential-like strings and PII before upload. |
| R7 | Releases can be verified by anyone and traced to their source. |

## 3. Threat model

### Assets

- The agent's credentials (`agent_secret`, access and refresh tokens).
- The privileges of the agent process (root or SYSTEM on every enrolled device).
- The integrity of the agent binary and its updates.
- The collected data (inventory, audit logs, task output).

### Attackers considered

| Attacker | Capability | Main defences |
|---|---|---|
| **Network attacker** | Reads or changes traffic between device and backend | HTTPS only, TLS 1.2+, certificate verification (R2) |
| **Unprivileged local user** | Writes files the agent reads (home directories, browser extensions, logs), names things, sets up `PATH` | Owner-only config (R3); parsers that validate input and are fuzzed; absolute paths for system binaries; values quoted before reaching a shell (R5) |
| **Malicious update or supply-chain attacker** | Tries to get a tampered binary onto devices, or slip changes into the repository or its dependencies | Ed25519 signature and SHA-256 verified before install, downgrades refused, pinned and scanned dependencies, protected `main`, attested and reproducible builds (R4, R7) |
| **Rogue or misconfigured backend client** | Has an agent's credentials, or tries to read another agent's data | Per-agent credentials, short-lived JWTs, Row Level Security on the backend (R1) |

### Out of scope (stated in `SECURITY.md`)

- **A compromised backend.** The backend can run scripts on every device by
  design. It is part of the trusted computing base.
- **A local administrator or root.** They already control the device and the agent.
- **Attacks on the device itself.** SentinelGo is a monitoring agent, not antivirus or EDR.

## 4. Trust boundaries

```text
            ┌───────────────────── device ─────────────────────┐
            │                                                   │
 unprivileged users ──(B2: files, logs, names)──▶ agent (root/SYSTEM)
            │                                    │   │          │
            │       (B3: argv) ◀─────────────────┘   │          │
            │   OS commands, fixed absolute paths    │          │
            └────────────────────────────────────────┼──────────┘
                                                     │ B1: HTTPS + JWT
                                                     ▼
                               operator's Supabase backend (trusted)
                                                     ▲
                                                     │ B4: signed release assets
                                    GitHub Actions release pipeline
```

| Boundary | Crossing | Controls |
|---|---|---|
| **B1** device ↔ backend | Telemetry, tasks, scripts, updates | HTTPS enforced at config load (`internal/config`); Go `crypto/tls` (TLS 1.2+, verified certificates); per-agent JWT with refresh; every call goes through `internal/supabase` with typed errors and one re-auth retry; RLS on the backend |
| **B2** local users → agent | Files, logs, extension manifests, account and adapter names read by a privileged process | Parsers validate their input and are fuzz-tested (`*_fuzz_test.go`, nightly fuzzing); values passed to PowerShell are quoted with `shared.PSQuote`; Go is memory-safe |
| **B3** agent → OS commands | The agent runs system tools to collect data | `internal/binpath` resolves tools to fixed absolute paths in administrator-only directories, not via `PATH`; arguments are passed as argv; timeouts on every command |
| **B4** release pipeline → devices | New agent binaries | Ed25519 signature (key compiled in, `internal/updater/pubkey.go`) and SHA-256 must both verify; strictly newer versions only; backup and rollback on a failed replace |

## 5. Secure-design principles

How the [Saltzer and Schroeder principles](https://en.wikipedia.org/wiki/Saltzer_and_Schroeder%27s_design_principles) apply:

| Principle | How SentinelGo applies it |
|---|---|
| **Economy of mechanism** | One static binary, no cgo, no runtime dependencies. All backend access goes through one package (`internal/supabase`), and no third-party Supabase SDKs are used. |
| **Fail-safe defaults** | Updates fail closed: no checksum, no signature, an older version or no backup means no update. A non-HTTPS backend URL is rejected at startup. |
| **Complete mediation** | Every backend request carries the agent's JWT and is checked by RLS on the backend. Every update is verified, every time. |
| **Open design** | The source, threat model and release process are public. Security rests on keys (the signing key, per-agent secrets), not on secrecy of the design. |
| **Separation of privilege** | The release signing key exists only as a CI secret, and releases are produced only by the release workflow after all checks pass. Changes reach `main` only through pull requests that pass the required checks, with no bypass for anyone. |
| **Least privilege** | Workflow tokens are read-only by default, with write permissions granted per job. The config file is owner-only (`0600`, or a SYSTEM/Administrators/agent DACL on Windows). The agent itself needs root or SYSTEM to read system logs and security settings. That is a known, documented necessity rather than a choice. |
| **Least common mechanism** | Each agent has its own credentials; nothing is shared between devices. |
| **Psychological acceptability** | Install is one command, updates are automatic, and installers verify checksums themselves, so the secure path is the easy path. |

## 6. Common weaknesses countered

| Weakness | Counter-measure | Evidence |
|---|---|---|
| Memory corruption (CWE-787, 125, 416) | Go is memory-safe; cgo is banned and checked in CI (`make check-no-cgo`). `unsafe` is used only for Win32 API calls in the Windows event-log collector. | `Makefile`, `CLAUDE.md` |
| OS command injection (CWE-78) | Commands get argv lists, not shell strings. The few PowerShell scripts that include device values quote them with `shared.PSQuote`, which is fuzz-tested. | `internal/osinfo/shared/psquote.go` |
| Untrusted search path (CWE-426/427) | `internal/binpath` resolves system tools to fixed absolute paths. | `internal/binpath` |
| Improper input validation (CWE-20) | Parsers of command output, logs, EDID data, extension manifests, versions and signatures have fuzz targets run nightly; malformed values are rejected. | `.github/workflows/fuzz.yml` |
| Download without integrity check (CWE-494) | Updater requires SHA-256 and an Ed25519 signature; installers require `SHA256SUMS`. | `internal/updater` |
| Cleartext transmission (CWE-319) | HTTPS enforced at config load; no HTTP fallback. | `internal/config` |
| Incorrect permissions (CWE-732) | Config and install directories get owner-only permissions on every platform. | `internal/config/secure_*.go`, `internal/winsec` |
| Hard-coded credentials (CWE-798) | No secrets in the binary or the repository; GitGuardian is a required check. | `SECURITY.md` |
| Sensitive data in logs or output (CWE-532) | `internal/sanitize` redacts credential-like strings and PII from task output and log lines. | `internal/sanitize` |
| Race conditions (CWE-362) | Tests run with the race detector in CI. | `.github/workflows/ci.yml` |
| Resource exhaustion (CWE-400) | Timeouts on every HTTP request and command; scripts over 10 MiB rejected; circuit breaker on failing calls. | `internal/httpx`, `internal/resilience` |
| Vulnerable dependencies (CWE-1395) | Dependabot, `govulncheck` and Trivy in CI; `go mod verify`; GitHub Actions pinned to commit SHAs. | `.github/` |

## 7. How the claims are kept true

- **Static analysis on every pull request:** CodeQL (high-severity alerts block merging), Semgrep (required), gosec, `go vet`, golangci-lint and SonarCloud.
- **Dynamic analysis:** nightly fuzzing; the race detector on every pull request.
- **Supply chain:** reproducible builds, signed releases, build-provenance and SBOM attestations, and OpenSSF Scorecard.
- **Process:** security-relevant changes are listed under **Security** in [`CHANGELOG.md`](../CHANGELOG.md), and vulnerabilities are handled as described in [`SECURITY.md`](../SECURITY.md).

## 8. Known gaps

These are tracked in [`ROADMAP.md`](../ROADMAP.md):

- The agent secret and tokens are stored in cleartext, protected only by file permissions.
- If an update installs but the new binary fails to start, there is no automatic rollback.
- No independent security review has been done yet.
