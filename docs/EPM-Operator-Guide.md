# SentinelGo EPM — Operator Guide

Endpoint Privilege Management (EPM) lets a standard (non-admin) user run a specific, pre-approved application with elevated privileges, without granting that user admin/root/Administrator rights generally. This guide covers enabling it, authoring policy, reading the audit trail, and current per-platform limitations.

Related: `docs/EPM-Capability-Assessment.md` (original gap analysis this feature was built against), `.kiro/specs/epm/{requirements,design,tasks}.md` (full spec and implementation status).

## 1. Enabling EPM

Add two fields to `config.json` (see `internal/config/config.go`):

```json
{
  "enable_epm": true,
  "epm_policy_sync_interval": "5m"
}
```

- `enable_epm` (bool, default `false`): the master switch. When `false` (the default), the agent behaves exactly as it does today — no EPM component starts, no new files are created, zero overhead.
- `epm_policy_sync_interval` (duration string, default `"5m"`): how often the agent proactively pulls pending `epm-policy-sync` tasks from the backend, independent of the general remote-task-polling interval (`task_polling_interval`). This means EPM policy delivery keeps working even if `enable_task_polling` is turned off for other reasons.

Restart the agent after changing `enable_epm`. On startup you should see:

```
EPM enabled (policy sync interval: 5m0s)
epm: Named Pipe IPC server listening on \\.\pipe\sentinelgo-epm       (Windows)
epm: Unix Domain Socket IPC server listening on /var/run/sentinelgo/epm.sock   (macOS/Linux)
```

If EPM fails to start (e.g. a locked database file), the agent logs a warning and continues running normally — EPM is treated as a best-effort optional component, the same as software-sync or services-collect.

## 2. Software Inventory Fields (sha256_hash and publisher)

Before writing hash- or publisher-based policy rules you need to know the exact values the agent will match against. Since v2 of the local software catalog schema, the agent now collects and stores two additional fields for every software entry:

| Field | JSON key | Description |
|---|---|---|
| `SHA256Hash` | `sha256_hash` | Lowercase hex-encoded SHA-256 of the installed binary identified by `file_path`. Populated by the enrichment pass that runs after collection; empty when `file_path` is unknown, the file is unreadable (e.g. SIP-protected on macOS), or a transient I/O error occurred. |
| `Publisher` | `publisher` | Vendor or signing authority. **Windows**: the `Publisher` registry value from the Uninstall key (same string shown in *Add/Remove Programs*). **macOS**: the `obtained_from` field from `system_profiler` — one of `apple`, `mac_app_store`, `identified_developer`, `developer_id`, or `unsigned`. **Linux / browser extensions**: empty (no equivalent metadata is available from package managers or extension manifests). |

### How hash caching works

Re-hashing every installed binary on every sync cycle would create significant disk I/O on machines with hundreds of packages. The agent avoids this by caching hashes in the local SQLite catalog (`sentinelgo_software.db`):

- On the first sync (or when a binary is newly seen), the hash is computed and stored.
- On subsequent syncs the cached hash is reused; `computeHash` is only called again if the entry has no cached hash yet (e.g. after a version upgrade that creates a new catalog row).
- A hash that cannot be computed (permission error, file removed mid-scan) is left empty for that cycle but does **not** overwrite a previously cached non-empty hash — so a transient failure never erases a known-good value.

### Using inventory data to author policy rules

These fields are included in every software-sync payload sent to the backend (`agent_enqueue_software` RPC), so they are available in the server-side software inventory tables. When authoring an EPM policy rule:

1. Look up the software entry in the inventory UI (or query the backend directly).
2. Copy `sha256_hash` into the rule's `app_hash` field for the most precise match.
3. Copy `publisher` into the rule's `publisher` field for a vendor-wide rule that survives version upgrades without needing to update the hash.
4. Use `app_path` only when neither hash nor publisher is available (e.g. a Linux binary not owned by any package manager).

> **Note:** `sha256_hash` in the inventory reflects the binary at the time of the last successful sync. If the software is upgraded between syncs the hash will be stale until the next cycle. For frequently-updated software, a `publisher`-based rule (which survives upgrades) is usually more maintainable than a `hash`-based rule.

## 3. Authoring Policy Rules

Policy rules are delivered to the agent as the payload of a remote task with slug `epm-policy-sync` (the same `agent_get_tasks` mechanism used for every other remote task type — no new backend endpoint is required). Example payload:

```json
{
  "rules": [
    {
      "id": "allow-diskutil-by-hash",
      "app_hash": "3f786850e387550fdab836ed7e6dc881de23001b",
      "decision": "allow",
      "priority": 300
    },
    {
      "id": "allow-acme-vpn-client",
      "publisher": "Acme Corp Code Signing",
      "decision": "allow",
      "priority": 200
    },
    {
      "id": "allow-specific-install-path",
      "app_path": "C:\\Program Files\\LegacyTool\\tool.exe",
      "decision": "allow",
      "user_id": "CONTOSO\\jsmith",
      "priority": 100
    },
    {
      "id": "allow-installer-glob",
      "app_path": "/opt/vendor/*/install.sh",
      "decision": "allow",
      "priority": 50
    },
    {
      "id": "deny-everything-else",
      "decision": "deny",
      "priority": 0
    }
  ]
}
```

### Rule fields

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Stable identifier. Re-sending a rule with the same `id` updates it in place (upsert); omitting a previously-sent `id` from a later sync deletes it (full-replace semantics — every sync is the complete, authoritative rule set). |
| `app_hash` | string | Lowercase hex SHA-256 of the target binary. Highest-priority match tier. |
| `publisher` | string | Code-signing identity: Authenticode signer name (Windows), `codesign` Authority (macOS), or package Maintainer/Vendor field (Linux). Second-highest match tier. |
| `app_path` | string | Exact path, or a glob (contains `*`/`?`/`[`) for a family of paths. Exact match outranks glob match. |
| `user_id` | string | Restricts the rule to one user (`DOMAIN\User` on Windows, plain username on macOS/Linux). Omit (`""`) to apply to any user. |
| `decision` | `"allow"` \| `"deny"` | What happens when this rule is the best match. |
| `expires_at` | RFC3339 string | Optional. Omit or send `""` for a rule that never expires. An expired rule is skipped as if absent. |
| `priority` | integer | Tie-breaker within the same match tier (see below) — higher wins. |

### Match precedence

When more than one rule could apply to a request, the engine (`internal/epm/policy.go`) picks the single best match using this tier order, highest first:

1. **Hash match** (300) — exact `app_hash` equality.
2. **Publisher match** (200) — exact `publisher` equality.
3. **Exact path match** (100) — exact `app_path` equality.
4. **Glob path match** (50) — `app_path` contains a glob pattern that matches.
5. **Wildcard** (10) — a rule with none of `app_hash`/`publisher`/`app_path` set, scoped only by `user_id` (e.g. "allow this user to elevate anything").

Within the same tier, higher `priority` wins. **No matching rule → deny by default.** There is no way to configure a global allow; every application must be explicitly matched by some rule to be elevated.

Because hash beats publisher beats path, you can safely combine a broad publisher-based allow rule with a specific hash-based deny rule to block one bad version of an otherwise-trusted vendor's tool, without needing to touch the publisher rule.

## 4. How a Request Actually Gets Elevated (per platform)

The end user runs the unprivileged CLI client, `sentinelgo-epm`:

```
sentinelgo-epm -app "C:\Program Files\LegacyTool\tool.exe"
sentinelgo-epm -app /opt/vendor/tool/install.sh -args "--yes --verbose"
```

The client is a thin front end — it carries no privilege of its own and cannot forge its identity to the agent:

- **Windows**: talks to a Named Pipe (`\\.\pipe\sentinelgo-epm`, ACL-restricted to Authenticated Users). The agent resolves the *caller's actual identity* from the OS itself (`GetNamedPipeClientProcessId` → `ProcessIdToSessionId` → `WTSQueryUserToken`), never from anything the client sends. On allow, the agent duplicates that session's token into a primary token and calls `CreateProcessAsUser`, launching the app with an elevated token attached to the user's own desktop.
- **macOS**: talks to a Unix Domain Socket (`/var/run/sentinelgo/epm.sock`). The agent authenticates the connection via `LOCAL_PEERCRED` and cross-checks it against the current console user (`/dev/console` ownership). On allow, it runs `launchctl asuser <uid> <path>` — the app keeps the daemon's own root privileges but renders on that user's desktop.
- **Linux**: same Unix Domain Socket transport, authenticated via `SO_PEERCRED`, cross-checked against the active `loginctl` session. On allow, the agent execs the target directly (keeping its own root privileges) with `DISPLAY`/`XAUTHORITY`/`WAYLAND_DISPLAY`/`DBUS_SESSION_BUS_ADDRESS` recovered from a live process in that user's session, so the elevated process can still open windows on their desktop.

All three platforms converge on the same principle: **the agent's own already-elevated privilege is extended to one specific, policy-approved process on the user's desktop — nothing is dropped, and nothing prompts the user for credentials a second time**, since the whole point of EPM is that policy already made the allow/deny decision.

## 5. Audit Trail

Every elevation attempt — allowed or denied — is recorded locally first (`epm_audit_log` table, durable across restarts and offline periods) and uploaded to Supabase on its own cadence (`epm-audit-sync` scheduler task, reusing the same flush interval and upload pipeline as OS-level audit logs), tagged with `log_category = "EPM_ELEVATION_LOG"` so it can be filtered independently from other audit events. A row is marked synced only after a confirmed successful upload; failures are retried on the next cycle, nothing is dropped.

Each record includes: request ID, resolved user identity, application path and hash, the decision, which policy rule (if any) matched, and the launch timestamp.

## 6. Current Limitations

- **Linux code-signature verification checks package-manager integrity, not a cryptographic GPG signature chain** — and this is a structural limitation of the Linux package managers themselves, not just an unfinished implementation detail. This was empirically tested (built a real GPG-signed test RPM, imported the key, installed it, and queried it): neither `dpkg` nor `rpm` retain a queryable, re-verifiable GPG signature for an *already-installed* package without the original `.deb`/`.rpm` file on hand — `rpm -q --qf '%{SIGPGP:pgpsig}'` returns `(none)` even for a package that `rpm -K` confirms is validly signed as a *file*, because the installed package database doesn't carry that tag forward. So `dpkg -V`/`rpm -V` (does the file still match what was recorded at install) plus the Maintainer/Vendor field remains the best generically-available check across distributions. A binary not owned by any package (e.g. something dropped directly into `/opt`) can only match by hash or exact path, never by publisher.
- **Windows Authenticode publisher extraction** identifies the leaf (end-entity) certificate among everything embedded in the signature — distinguishing it from intermediate/root CA certificates also present — by checking which certificate's Subject never appears as another certificate's Issuer in the same chain. Verified against a real, multi-certificate-chain-signed system binary (`explorer.exe`, which embeds a full leaf→intermediate→root chain), correctly resolving to the leaf's name rather than a CA name. This covers the standard single-chain case; a signature using cross-signing (rare) could still be ambiguous.
- **Multi-session support differs by platform.** Windows and Linux resolve the identity of the *specific session the requesting client is running in* (via `ProcessIdToSessionId` on Windows, via `/proc/<pid>/environ`'s `XDG_SESSION_ID` on Linux) — so a second concurrent login (an RDP session on Windows, a background terminal or non-focused desktop on Linux) can request elevation, not only the one currently in focus. **macOS is still restricted to the single active console user** (`/dev/console` ownership) — there is no macOS equivalent as directly queryable as Windows' session IDs or Linux's logind session properties for "which GUI session does this specific connecting process belong to," and implementing one reliably without real Mac hardware to validate Fast User Switching against was judged too risky to attempt blind.
- **macOS/Linux launch PID reporting**: because the actual launch goes through `launchctl asuser` (macOS) or is otherwise wrapped, the PID recorded is the immediate child the agent started, which may itself be a launcher/wrapper process rather than the final application PID.
- **No GUI session on a headless/non-interactive host**: all three platforms require an active console/interactive session to resolve "who is the user" — EPM has no meaning on a server with nobody logged in, and elevation requests will fail to resolve an identity in that state (fails safe: no session found → error, never a guess).
- **Wayland**: the Linux launcher propagates `WAYLAND_DISPLAY`, `XDG_SESSION_TYPE`, and `XDG_CURRENT_DESKTOP` into the elevated process's environment (in addition to the X11 `DISPLAY`/`XAUTHORITY` pair), since GTK/Qt applications and the `xdg-desktop-portal` machinery commonly branch on these to pick a rendering backend and portal implementation. This is a defensive improvement based on documented variable semantics, **not confirmed by testing against a real GNOME/KDE Wayland session** — no such environment was available to validate against.
- **Real-hardware validation of the actual elevate-and-launch step remains outstanding on all three platforms.** `go build`/`go test ./...` have been run for real — not just cross-compiled — on Windows (native), Linux (Ubuntu 26.04 via WSL2), and macOS (real Apple Silicon hardware over SSH), and the Named Pipe transport was end-to-end tested on Windows with the privileged primitives stubbed. What has *not* been exercised on any platform is the actual privileged launch against a real interactive desktop login (real WTS session + `CreateProcessAsUser`, real `launchctl asuser`, a real logind session with `/proc/<pid>/environ` GUI variables) — that needs a real interactive session, which SSH/WSL shells do not provide. Treat a first production rollout on each platform as a pilot.

## 7. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `sentinelgo-epm: connect to ... (is the agent running with EPM enabled?)` | `enable_epm` is `false`, or the agent hasn't restarted since enabling it. |
| Elevation always denied, even for an app you added a rule for | Check the rule's match field actually matches what the agent computes — hash and publisher must match exactly; verify with the audit log's recorded `app_hash`/policy_id (or lack thereof) for the denied request. |
| Policy changes don't take effect | Rules are re-read fresh from local SQLite on every request (no in-memory staleness), but the *sync from the backend* to local SQLite depends on the `epm-policy-sync` task actually being delivered and processed — check agent logs for `epm-policy-sync: processed N pending policy-sync task(s)`. |
| No audit events appearing in Supabase | Confirm `audit_logs_enabled` is also `true` — EPM audit upload rides the same logging pipeline and is a no-op if that pipeline isn't running. |
