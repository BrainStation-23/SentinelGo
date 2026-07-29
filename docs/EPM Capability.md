SentinelOps (Forntend+DB)


The one fact that governs every answer below
This repo contains only the management plane (Web UI, PostgreSQL schema, RBAC, RPCs, policy authoring, audit viewing). The enforcement plane — the SentinelGo agent that actually runs on the endpoint, intercepts launches, and elevates a process — is a separate repo not present here. So every "✅" below means "can be correctly authored and dispatched as a policy", not "independently verified to work on a real Windows/macOS/Linux desktop." Real-hardware elevate-and-launch validation is documented as still outstanding.

1. Core Objectives
Objective	Status
Eliminate permanent local admin accounts	✅ Architecturally the point of the whole system — default-deny, no standing admin grants
Enforce least privilege	✅ Default-deny rule engine, no global-allow escape hatch
Reduce ransomware risk	🟡 Indirectly, via least-privilege — but no reputation/behavioral/child-process-containment features (see §Security below)
Prevent unauthorized software install	🟡 Only for installers you explicitly pin (MSI/EXE/PKG/DEB) — no "block unknown installer" global mode
Control privilege elevation	✅ Core feature, mature
Audit every privileged action	🟡 Logged, but retention is currently only 7 days (piggybacks on the general audit_logs table)
Simplify IT operations	🟡 Guided Templates help, but every scenario still requires hand-authoring exact paths/args/hashes — no true "operation catalog"
2. Architecture
Matches the diagram you pasted almost exactly: Console → policy sync (via agent_command_tasks, slug epm-policy-sync) → agent → policy evaluation → allow/deny → execute → audit report-back. One gap: there's no dedicated "Prompt" outcome in the schema (decision is only allow/deny) — a user-facing "are you sure?" prompt-before-elevate isn't a policy option, only silent match-or-deny.

A. Application Elevation — ✅ Fully supported
The most mature part of the system. Hash / publisher / path matching, wizard, rule editor, preview simulator, audit trail — all built and working end-to-end.

B. Application Whitelisting — matching methods
Method	Status
Executable Path (exact or glob)	✅
File Hash (SHA-256)	✅
Publisher Certificate	✅ (Authenticode name / macOS Team ID / Linux Maintainer field)
Script/Installer Hash	✅ (a 4th method you didn't list — matches installer/script payloads launched via an interpreter)
Product Name	❌ Not a rule field
File Name (name-only, path-independent)	❌ Not a rule field
MSI Product Code	❌ Not a rule field — MSI is handled via hash-pinning the .msi file itself, not its Product Code GUID
Bundle Identifier (macOS)	❌ Not a rule field
Package Name (Linux)	❌ Not a rule field
C. Rule-Based Elevation
Rule type	Status
Always Allow	✅
Always Deny	✅
Elevate for a fixed duration (JIT expiry)	✅ — presets: 30 min / 1 hr / 4 hr / 1 day / 1 week / permanent (not literally "15 minutes," but arbitrary expires_at is supported)
Ask for Justification	🟡 Only on the self-service request path (≥20 chars enforced server-side) — a directly policy-matched elevation is silent, no justification prompt
Require Approval	✅ — single-reviewer approve/deny workflow
Elevate Once (single-execution)	🟡 Approximated via a short time window (e.g. 30 min), not a true "consumed after first launch" semantic — user could launch more than once inside that window
Elevate Only During Business Hours	❌ No time-of-day/day-of-week condition anywhere in the schema
Elevate Only When on Corporate Network	❌ No network-location condition anywhere in the schema
D. Temporary Elevation (JIT) — ✅ Fully supported
Request → approve → timed grant → auto-expiry. Implemented in schema (expires_at, requested_duration_minutes) and UI.

E. Self-Service Elevation — ✅ Fully supported
Standard users can request elevation for a device without IT contact; employee/department_administrator roles are scoped to request-only (can't author policy).

F. Approval Workflow — 🟡 Partially supported
Single-tier approve/deny exists, with dual-control (an admin can no longer approve their own request — this was a security fix). Not supported: your example's multi-tier chain (Help Desk → Security Team, multiple required approvers). There's exactly one reviewer role/step, not a configurable escalation chain.

4. Application Control
Capability	Status
Allow	✅
Deny	✅
Allow Trusted Publishers	✅ (publisher-tier matching)
Audit Only / Monitor (log without enforcing)	❌ No "monitor mode" — every rule is enforcing
Block Unknown Software	🟡 Implicit consequence of default-deny, but not a labeled policy mode
Block Unsigned Applications	❌ No "require valid signature" global policy — you can choose publisher-tier matching per rule, but there's no blanket "reject anything unsigned" switch
5. Command Control (PowerShell / Bash / CMD)
🟡 Partially supported, uniformly across all three shells. The mechanism: pin the interpreter path (powershell.exe, /bin/bash, cmd.exe) + allowed_args set to one exact command line. This works, but:

It's one rule per exact command line — there's no list/array of approved commands on a single rule, and no pattern-based allow (e.g., "any Get-* cmdlet").
CMD specifically has no dedicated Guided Template (unlike PowerShell/Bash) — same underlying mechanism would apply, but nobody has wired it up with presets yet.
Restricting everything else (e.g., blocking Remove-Computer, sudo su, net user administrator) is a side-effect of default-deny, not an explicit blocklist — ✅ for "unapproved stays blocked," ❌ for "named-command blocklist with an otherwise-open shell."
6. Windows Service Control — 🟡 Partially supported
Start/Stop/Pause/Resume via sc.exe, Restart via a PowerShell wrapper (since sc.exe has no restart verb), all scoped to one named service via allowed_service_name (fail-closed if the name can't be matched). Gap: not integrated with Windows SCM's own security-descriptor delegation (sc sdset) — correctness depends entirely on how precisely the admin authors the rule.

7. Windows IIS Management — 🟡 Partially supported
Start/Stop/Restart website, Create/Start/Stop/Recycle app pool, and config get/set all have Guided Templates via appcmd.exe scoped by site/pool name. Gaps:

"Restart" is stop-then-start — not atomic (appcmd.exe has no atomic restart verb).
"Open IIS Manager" elevates the full GUI — there's no equivalent of IIS's own per-site delegation, so this can't be scoped to one site/pool the way you'd want.
10. File & Folder Privilege Management — ❌ Not supported
No file-ACL-aware or resource-scoped enforcement anywhere in the schema. Only "which exact binary/script may run" is enforceable — nothing understands "this file" or "this folder" as a governed resource.

11. Hosts File Management — ❌ Not supported as a dedicated capability
Zero references to hosts or the hosts file path anywhere in the codebase. Achievable only indirectly: hash-pin one specific script whose job is editing the hosts file, elevate that exact script. That's a real, working path — but it's "elevate this one approved script," not a feature that understands "the hosts file."

12. Device Management Operations — 🟡 Exists, but outside EPM entirely
Your platform does have Reboot, Firewall Enable/Disable, USB Storage Enable/Disable, BitLocker Enable, OS Patch/Upgrade, Set Hostname, Lock Device, Wipe User Profile (see public/seed/sentinelops-commands.json) — but as a separate, pre-existing "Commands" system, always run with full agent privilege, unrelated to EPM's user-elevation model. Missing entirely, in any system: Flush DNS, Renew IP, Join Domain, Leave Domain, Restart Network Adapter — none of these exist as commands today.

13. Installer Control
Type	Status
MSI	✅ Guided Template (hash-pinned via msiexec.exe)
EXE	✅ Guided Template (hash-pinned)
PKG (macOS)	✅ Guided Template (via installer(8))
DEB	✅ Guided Template (via dpkg)
DMG (macOS)	❌ No template (mechanism would apply, but nothing pre-built)
RPM	❌ No template (dnf/yum/pacman not covered yet)
Approval/Justification-required gating on installers: 🟡 same generic approval-request path as any other elevation, not installer-specific policy fields.

14. Script Control — ✅ Mostly supported
This is the mechanism the schema was actually built around: hash-pin the script + pin the interpreter path. Validated by File Hash ✅ and Publisher/Digital Signature ✅ and Path ✅. VBScript — not explicitly templated (mechanism applies, no preset). Batch files (.bat/.cmd) — same, no dedicated template but the generic path+hash mechanism works.

15. Elevation Methods
Method	Status
Automatic (silent policy match)	✅
Temporary Admin (JIT)	✅
Run Once	🟡 Approximated via short expiry window, not true single-execution consumption
Justification	🟡 Self-service request path only
Approval	✅ (single-tier)
Prompt (ask user before elevating, outside the request flow)	❌ Not a schema concept — decision is only allow/deny, no interactive-prompt outcome
Device Context Conditions — ❌ Not wired into EPM
Your platform does have a device compliance/posture engine (src/lib/posture.ts) tracking Firewall, Antivirus/Defender, Secure Boot, Core Isolation, USB storage, BitLocker/recovery-key status, and an overall compliance grade. But none of this is a condition an EPM rule can check — EPM policies target only a device or a device group, not "only elevate if BitLocker is on" or "only if domain-joined." OS/Windows-version/macOS-version/Linux-distro, Domain/Hybrid/Azure-AD-joined, Risk Level — none of these gate an elevation decision today.

18. Security Features
Feature	Status
Least Privilege Enforcement	✅
Hash Verification	✅ — strongest-verified area (agent recomputes hash server/agent-side, doesn't trust client claims per docs)
Digital Signature / Publisher / Trusted Publisher Verification	✅ on Windows (Authenticode); 🟡 weaker on Linux (matched against package Maintainer field, not a GPG chain)
Anti-Tampering, Policy Integrity Validation, Offline Policy Cache, Secure Policy Sync, Credential Protection, Privilege Removal	❓ Cannot be verified — these are agent-plane behaviors, and the agent code isn't in this repository
Child-process containment	❌ Not present — flagged as an open, unmitigated risk in the project's own feasibility doc
DLL-sideloading / file-integrity protection for elevated processes	❌ Not present beyond pinning the parent binary's hash
19. Audit & Logging — fields actually captured per elevation event
✅ User, Device, Hostname, App Path, App Hash, Policy/Rule Applied, Elevation Result (allow/deny), Script Hash, Service Name, Timestamp.
🟡 Justification, Approval ID — captured only for the self-service request flow, not for direct silent policy matches.
❌ Not captured: IP Address, Exit Code, Process Tree, Parent Process, Child Processes, Publisher (not stored on the log row itself, only on the rule).

Also a real limitation: elevation logs live in the general audit_logs table, which is pruned to 7 days — so anything relying on 30/90/365-day history (see next section) is running against data that mostly won't exist that far back.

20. Reporting & Analytics
Dashboard	Status
Most Denied Applications	✅
Top Users by Elevation Requests	✅
Policy/Rule Usage counts	✅
Failed Elevation Attempts	✅ (deny counts)
Rules Expiring Soon	✅ (bonus, not on your list)
Most Elevated (allowed) Applications	❌ Only denies are ranked, not top allowed apps
Approval Trends	❌
Security Events	❌
Risky Applications	❌
Software Installations report	❌ (exists elsewhere in the product's software inventory, not in EPM analytics)
Compliance Reports	❌
SIEM/webhook alerting	❌ Not found anywhere in the repo
22. Platform Support
🟡 Architecturally intended for Windows/macOS/Linux — schema and templates are OS-agnostic and cover all three. But since the enforcement agent isn't in this repo, real cross-platform parity is unverified; the agent's own documentation reportedly states real-hardware elevate-and-launch testing is still outstanding on all three OSes.

Bottom line
The policy-authoring layer is genuinely strong for its core use case — elevate a specific approved app/script by hash, publisher, or path, with JIT expiry, self-service request, and approval. That part is close to commercial-grade.

Everything else on your list (IIS, service control, hosts file, PowerShell/Bash/CMD command sets, installers) is reachable only by hand-crafting the same generic path+hash+args rule under a different label — there is no dedicated schema concept for "this is an IIS operation" or "this is a hosts-file edit." That's a deliberate, defensible architecture (maximally flexible), but it means none of those six scenarios is a discrete, hardened feature the way application elevation is.

Completely absent today, in any form: device-context/compliance-conditioned rules (business hours, network location, BitLocker/domain-join status), multi-tier approval chains, reputation/behavioral controls, child-process containment, DLL-sideloading protection, SIEM alerting, and compliance-grade (1yr+) audit retention.

Biggest unknown: since the actual enforcement agent isn't in this repository, none of the "✅" verdicts above have been confirmed to work on a real desktop — that would need a review of the separate SentinelGo agent repo.



=====================


SentinelGo agent


Important caveat first
This repo is only the management plane (Web UI, Postgres schema, RBAC, policy authoring, audit viewing). The enforcement agent that actually runs on endpoints and elevates processes lives in a separate repo. So every ✅ below means "policy can be correctly authored," not "verified working on a real desktop." Real-hardware testing is still outstanding.

✅ Fully Supported (mature, working end-to-end)
Application elevation — hash / publisher / path matching, wizard, rule editor, simulator, audit trail
App whitelisting by: Executable Path, File Hash (SHA-256), Publisher Certificate, Script/Installer Hash
Always Allow / Always Deny rules
JIT (temporary) elevation with expiry presets (30min → permanent)
Require Approval workflow (single reviewer, with dual-control so admins can't approve their own requests)
Self-service elevation requests (no IT contact needed)
Installer control for MSI, EXE, PKG (macOS), DEB
Least privilege enforcement — default-deny, no global-allow bypass
Hash verification — strongest area; agent recomputes hashes rather than trusting client claims
🟡 Partially Supported (works, but limited)
Ransomware risk reduction — only via least-privilege; no behavioral/reputation/child-process containment
Command control (PowerShell/Bash/CMD) — one rule = one exact command line, no pattern matching or command lists; CMD has no guided template yet
Windows Service Control — start/stop/pause/restart per named service, but not integrated with Windows SCM's own delegation
IIS Management — most operations covered, but "Restart" isn't atomic and can't be scoped like native IIS delegation
Approval workflow — single-tier only, no multi-step escalation chains
Justification requirement — only on self-service requests, not on direct policy matches
"Elevate Once" — approximated via short time window, not true single-use consumption
Audit retention — only 7 days (shared general audit_logs table)
Linux publisher verification — matched against Maintainer field, not a real GPG signature chain
❌ Not Supported at All
Monitor/Audit-only mode (every rule enforces, nothing is log-only)
Block unsigned software (no global "reject unsigned" switch)
Time/day conditions (business hours, day-of-week)
Network-location conditions (corporate network only, etc.)
Device posture/compliance conditions (BitLocker, domain-join, OS version) — posture data exists elsewhere but isn't wired into EPM rules
"Prompt before elevate" outcome — decisions are only allow/deny, no interactive ask
File/Folder ACL management — nothing understands "this file" or "this folder" as a resource
Hosts file management as a dedicated feature (only achievable by hash-pinning a custom script)
DMG and RPM installer templates
Child-process containment / DLL-sideloading protection
SIEM/webhook alerting
Compliance-grade long-term audit reports (30/90/365-day) — data doesn't live that long
Advanced reporting: Approval trends, Security events dashboard, Risky apps, Compliance reports, Top allowed apps (only denies are ranked)
Flush DNS / Renew IP / Join-Leave Domain / Restart network adapter commands
Bottom line
Core elevation (allow a specific app/script by hash/publisher/path + JIT + approval + self-service) is genuinely strong and near commercial-grade. Everything else (IIS, services, hosts file, shell commands, installers) works only by hand-crafting the same generic "path+hash+args" rule — there's no dedicated schema for those scenarios. Biggest gaps: no conditional rules (time/network/device-posture), no monitor-only mode, and no multi-tier approvals. And since the enforcement agent isn't in this repo, none of this is confirmed working on real hardware yet.