# 09 — Remaining Enterprise Gaps: Design Recommendations

**Design only. Nothing here is implemented.**

Every category in [02-gap-analysis.md](02-gap-analysis.md) that a telemetry
collector now fills has been removed from this list. What remains are the six
gaps that are still open, with a recommended mechanism, an honest cost, and a
recommendation on whether to build it.

The list is ordered by value per unit of risk, not by how interesting the data
is.

---

## Summary

| # | Gap | Recommendation | Effort | Why |
|---|---|---|---|---|
| 1 | Browser classification | **Build — small** | ~1 day | Pure derivation from data already collected; no new OS calls, no new platform code |
| 2 | Local account metadata | **Build — medium** | ~3 days | Real compliance value (dormant and stale-password admin accounts); extends a collector that already exists |
| 3 | Recovery-key escrow status | **Build — medium, Windows first** | ~2 days | The single highest-value item for a BitLocker fleet: it answers "can we actually recover this disk" |
| 4 | Wi-Fi BSSID / channel / auth | **Defer** | ~3 days | Real value is narrow (roaming and rogue-AP work) and the data is volatile |
| 5 | OS end-of-support date | **Build — small, but not as a collector** | ~1 day | Endpoint-side collection is the wrong design; see below |
| 6 | Peripheral and printer detail | **Defer** | ~2 days | Extends working collectors for modest value |

---

## 1. Browser classification — build

**Gap.** Gap-analysis item 26. Installed browsers are already in the software
inventory; nothing marks them as browsers or extracts their versions for
vulnerability matching.

**Recommendation.** A **derivation over the existing software inventory**, not a
collector. No new OS calls, no new platform files, nothing new to validate on
three platforms — which is why this is the cheapest item on the list.

Match on the identifiers already collected (`Name`, `SoftwarePackage`,
`FilePath`) against a small known-browser table: Chrome, Edge, Firefox, Safari,
Brave, Opera, Vivaldi, Chromium. Emit a `browsers` section with name, version,
channel where derivable, and the source package.

**Where it belongs.** A new collector in `internal/telemetry/collectors/browsers/`
that calls the software collector read-only — the same pattern as the `bridge`
package, and for the same reason: one implementation of "what is installed".

**Caveat worth stating.** This reports installed browsers, not *default* or
*in-use* browsers. Default-browser resolution is per-user and the agent runs as
a system service; claiming otherwise would repeat the proxy-detection caveat
already documented in the network collector.

## 2. Local account metadata — build

**Gap.** Gap-analysis item 19. Local accounts and groups are collected, but not
enabled/disabled state, last login, password age, or the admin/sudo flag.

**Why it is worth it.** These four fields answer questions an inventory cannot:
which admin accounts have never been used, which have passwords older than
policy, which disabled accounts are still present. Dormant privileged accounts
are a standard audit finding.

**Mechanism.**

| Field | Windows | Linux | macOS |
|---|---|---|---|
| Enabled/disabled | `Win32_UserAccount.Disabled` (WMI) | `/etc/shadow` field 2 (`!`/`*` prefix) | `dscl . -read /Users/x AuthenticationAuthority` |
| Last login | `Win32_NetworkLoginProfile.LastLogon` | `lastlog` / `/var/log/wtmp` | `last -1 <user>` |
| Password age | `Win32_UserAccount.PasswordChangeable` + net user | `chage -l` or `/etc/shadow` field 3 | `pwpolicy -u <user> -getpolicy` |
| Admin / sudo | Local Administrators group | `sudo`/`wheel` group + `/etc/sudoers.d` | `admin` group |

**Design notes.** Extend the existing `security_posture` collector rather than
adding a section: it already collects `privileged_accounts` and password policy,
so the data belongs with it and no new section name enters the backend contract.

**Two traps.** `/etc/shadow` is root-only — report `permission_denied` rather
than an empty result if the agent is somehow not root. And last-login timestamps
are **volatile**: they must be excluded from the section fingerprint, or every
login re-uploads the whole section. This is the same defect that made the
software inventory re-upload on every application launch.

## 3. Recovery-key escrow status — build, Windows first

**Gap.** Gap-analysis item 6. Per-volume encryption detail and key protector
types are now collected; whether the recovery key is **escrowed** is not.

**Why it is the highest-value item here.** "Is this disk encrypted" is already
answered. The question an operator actually needs answered during an incident is
"if this machine locks us out, can we recover it" — and an encrypted disk whose
recovery key was never escrowed is arguably worse than an unencrypted one.

**Mechanism.**

- **Windows:** `manage-bde -protectors -get <drive>` reports whether a key
  protector has been backed up to AD DS or Entra ID. `Get-BitLockerVolume`'s
  `KeyProtector` collection (already read by the encryption collector) can be
  extended rather than replaced.
- **macOS:** `fdesetup haspersonalrecoverykey` and
  `fdesetup hasinstitutionalrecoverykey` — both cheap, both non-interactive.
- **Linux:** ❌ **no standard escrow concept exists.** LUKS key slots can be
  enumerated with `cryptsetup luksDump`, but there is no notion of escrow to a
  directory service. Report `unavailable_on_os` — a real platform limitation, and
  exactly the case that state exists for.

**Design note.** Add to the existing `encryption` section as
`recovery_key_escrowed` (`*bool` — nil where undetermined, never a guessed
false) plus `escrow_target` (`"ad"`, `"entra"`, `"institutional"`, `"personal"`).
A nil, not a false, is the difference between "not escrowed" and "we could not
tell", and only one of those warrants a ticket.

**Sequencing.** Windows first. It is where BitLocker fleets live, it is the only
platform with a true escrow answer, and macOS can follow independently.

## 4. Wi-Fi BSSID / channel / auth — defer

**Gap.** Gap-analysis item 12. SSID, signal and band are collected; BSSID,
channel, and authentication/encryption type are not.

**Mechanism** (for the record): Windows `netsh wlan show interfaces`; macOS
`wdutil info` (the `airport` binary was removed in macOS 14); Linux
`iw dev <if> link` or `nmcli -f ALL dev wifi`.

**Why defer.** Three reasons, in order:

1. **The data is volatile.** BSSID and channel change whenever a laptop roams
   between access points — several times a day in an office. In a fingerprinted
   section that is constant churn, so it would need either its own section or
   deliberate exclusion from the fingerprint. Either is more design than the
   value justifies right now.
2. **The value is narrow.** It matters for roaming diagnostics and rogue-AP
   detection. Neither is a current requirement.
3. **macOS is a moving target.** `airport` is gone; `wdutil` output format is
   undocumented and has changed between releases.

**Reconsider if** rogue-AP detection or wireless roaming diagnostics become a
requirement. Then model it as its own non-fingerprinted section, the way
`health` is.

## 5. OS end-of-support date — build, but not as a collector

**Gap.** Gap-analysis item 2.

**Recommendation: do not collect this on the endpoint.** An end-of-support date
is a property of an OS *version*, not of a machine. Collecting it per endpoint
means either shipping a lookup table inside the agent — which goes stale between
agent releases and needs a new binary rollout to fix a date — or having 10,000
endpoints each query an external source.

**Better design.** The agent already reports OS name, version and build in the
`os` section. The backend maps `(os_name, version, build) → EOS date` from a
table it can update centrally, without touching a single endpoint. The lookup is
correct for the whole fleet the moment the table is updated.

**What the agent should add**, if anything: nothing new for Windows or macOS.
For Linux, `/etc/os-release`'s `VERSION_ID` and `VERSION_CODENAME` make the
backend's lookup unambiguous across distributions; both are cheap file reads and
worth adding to the `os` section regardless.

## 6. Peripheral and printer detail — defer

**Gap.** Gap-analysis items 24 and 25. Peripherals lack device class and
connected state; printers lack port, default flag and real status, and DPI is
guessed from driver names.

**Mechanism** (for the record): Windows `Win32_PnPEntity.PNPClass` and
`Win32_Printer.PortName/Default/PrinterStatus`; Linux `/sys/bus/usb/devices/*/bDeviceClass`
and `lpstat -p -d`; macOS `system_profiler SPUSBDataType` and `lpstat`.

**Why defer.** The value is modest — peripheral class helps USB-policy work,
and the printer fields are mostly a helpdesk convenience. Meanwhile the
existing collectors work, `system_profiler` is one of the more expensive calls
the agent makes, and connected-state is volatile in the same way §4 is.

**One thing worth doing cheaply now:** the guessed printer DPI should be dropped
rather than improved. A guessed value that looks like a measurement is worse
than an absent one, which is the same principle behind the nil-not-false rule
used throughout the telemetry collectors.

---

## Not on this list

Two items from earlier gap analysis are deliberately absent:

- **ARP / neighbour table.** Enumerating other hosts on the local network is a
  different dataset with a different privacy profile — it is data about machines
  that are not this endpoint. If it is ever wanted it needs its own opt-in flag
  and its own privacy review, not an extension of the routing-table collector.
- **DLP.** Out of scope for this work by explicit decision; the architecture
  only avoids foreclosing it.
