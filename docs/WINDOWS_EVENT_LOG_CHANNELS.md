# Windows Event Log Channels Being Captured

Only **high** and **critical** audit logs are sent to the backend (#484). The
backend is a compliance platform, not a log store, so routine events stay on
the device.

The OS level alone doesn't say what matters: Windows logs failed logons and
account changes at Information level and Defender detections at Warning level.
So the agent:

1. asks each channel only for Critical and Error events (Level 1–2) and the
   event IDs listed below;
2. grades each event: the Windows level, raised for the listed event IDs
   (`internal/auditlogs/parser/grade.go`; a rule never lowers a severity);
3. drops everything below `high` and counts it (`DroppedLowSeverity`,
   `sentinelgo -logging-stats`).

| Windows level | Severity | Sent |
|---|---|---|
| Level 1 (Critical) | `critical` | yes |
| Level 2 (Error) | `high` | yes |
| Level 3 (Warning) | `medium` | only when re-graded |
| Level 4 (Information), Security log (0) | `info` | only when re-graded |
| Level 5 (Verbose) | `info` | only when re-graded |

## Security channel (3 queries)

| Query | Source | Event IDs | Severity |
|---|---|---|---|
| Failed logons | `windows_security` | 4625 | high |
| Accounts and groups | `windows_security` | 4720, 4722, 4723, 4724, 4725, 4726, 4738 (account created, enabled, password changed or reset, disabled, deleted, changed); 4731, 4732, 4733, 4734 (local group created, member added, member removed, group deleted) | high |
| Policy | `windows_security` | 1102 (Security log cleared), 4719 (audit policy changed) | critical |
| | | 4739 (domain policy changed) | high |

The real-time subscription follows 1102, 4625, 4719, 4720, 4722, 4724, 4725,
4726 and 4732. Collection picks them up too; the store de-duplicates.

Not collected (routine, high volume): 4624 logon, 4634 logoff, 4648
explicit-credential logon, 4672 special-privilege logon, 4656/4663/4670 object
access, 4688 process creation, 5156/5157 Windows Filtering Platform
connections.

## Other channels

| Channel | Source | Collected | Re-graded |
|---|---|---|---|
| System | `windows_system` | Level 1–2, 104, 7045 | 104 (an event log cleared): critical; 7045 (service installed): high |
| Application | `windows_application` | Level 1–2 | — |
| Windows Defender | `windows_microsoft_windows_windows_defender_operational` | Level 1–2 and the IDs on the right | critical: 1006, 1015, 1116 (malware or suspicious behaviour detected), 1008, 1118, 1119 (action on malware failed), 5001 (real-time protection disabled), 5010, 5012 (scanning disabled); high: 1007, 1117 (action taken), 5004, 5007 (configuration changed), 5013 (tamper protection blocked a change) |
| PowerShell | `windows_microsoft_windows_powershell_operational` | Level 1–2, 4104 at Warning | 4104 at Warning (script block Windows flagged as suspicious): high |
| Task Scheduler | `windows_microsoft_windows_taskscheduler_operational` | Level 1–2, 106 | 106 (task registered): high |
| Windows Firewall | `windows_microsoft_windows_windows_firewall_with_advanced_security_firewall` | Level 1–2, 2003 | 2003 (profile setting changed): high |
| Remote Desktop | `windows_microsoft_windows_terminalservices_remoteconnectionmanager_operational` | Level 1–2, 1149 | 1149 (remote desktop sign-in): high |
| Group Policy | `windows_microsoft_windows_grouppolicy_operational` | Level 1–2 | — |

The time-service events (System 24 and 35) are no longer collected.

## Linux and macOS

- **Linux:** `journalctl` reads priority err and above (0–3) and the auth and
  authpriv facilities. Files: `auth.log`, `syslog`, `messages`, `kern.log`.
- **macOS:** `log show` reads `error` and `fault` messages and the `sudo`,
  `sshd` and `su` processes (no `--info`). Files: `system.log`, `install.log`;
  crash reports are critical.
- On both, sign-ins and account changes are graded **high** by message:
  sshd failed and accepted sign-ins (`sshd-session` from OpenSSH 9.8), sudo and
  su failures, and useradd, userdel, usermod, groupadd, groupdel, gpasswd,
  chpasswd and `passwd` password changes.

---

*Configuration: `internal/auditlogs/collector/collector_windows.go` (queries),
`internal/auditlogs/parser/grade.go` (grading).*
