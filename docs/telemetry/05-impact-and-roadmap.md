# 05 — Impact Analysis and Roadmap

*Deliverables 12–15: performance, privacy/security, backend compatibility, and the phased plan.*

---

## 1. Performance impact

### The current budget

`osinfo.Collect()` runs every 5 minutes under a 90-second timeout. On Windows the security package alone fires roughly 20 PowerShell invocations at 350–900 ms cold each; a realistic total today is 20–60 seconds. **There is very little headroom left on Windows**, which drives every decision below.

Additional fixed costs already being paid: `cpu.Percent(time.Second, false)` blocks a full second, and `system_profiler` costs 1.5–4 seconds per invocation on macOS.

### Cost of the new layer

| Addition | Windows | macOS | Linux | Where it runs |
|---|---|---|---|---|
| Foundation (Phase B) | ~0 | ~0 | ~0 | no collectors registered |
| Identity + VM detection | ~150 ms (WMI) | ~50 ms (`ioreg`) | ~5 ms (sysfs) | telemetry task |
| Directory join | ~600 ms (`dsregcmd`) | ~200 ms | ~100 ms | telemetry task |
| Sessions | ~300 ms | ~100 ms | ~50 ms | telemetry task |
| SMART | +1 PS call (1.5–3 s) + WMI ~100 ms | ~100 ms | ±0 (replaces existing call) | telemetry task, 30-min cache |
| Volumes | ~500 ms | ~300 ms | ~50 ms | telemetry task |
| Battery | ~100 ms (native WMI) | ~50 ms (`ioreg`) | ~5 ms (sysfs) | telemetry task |
| Processes | 0.3–1.5 s | 0.2–0.8 s | 50–200 ms | own cadence, default off |
| Persistence | 2–6 s (`Get-ScheduledTask`) | 50–200 ms | ~50 ms | own cadence |
| Patches | 2–8 s (Windows Update COM) | 1–3 s | 0.5–2 s | 6-hourly |
| Certificates | ~500 ms | ~300 ms | ~200 ms | 12-hourly |

### Mitigations, in order of impact

1. **The telemetry task is separate from `osinfo.Collect()`.** The 90-second legacy budget is untouched — the expensive new datasets never enter it.
2. **Separate collect and reconcile intervals.** Static hardware is read every 6 hours, not every 5 minutes.
3. **Staggered cadences.** Not every collector runs on every tick; the scheduler's existing startup jitter spreads fleet-wide load.
4. **SMART caching** at 30 minutes. SMART is hours-scale data: power-on hours ticks once an hour, wear level moves about 1% a month. Reading it every cycle is pure waste, and caching cuts the Windows cost roughly sixfold.
5. **Windows scheduled-task filtering** by default: ~400 tasks down to ~30, cutting both runtime and payload by about 90%.
6. **Native APIs where they pay:** native WMI for battery is ~100 ms against ~3 s for four PowerShell launches; `ioreg` is ~30 ms against 1.5–4 s for `system_profiler`.
7. **Processes default to off**, being the highest-volume and highest-cost dataset.

### Fleet scalability at 10,000 endpoints

Per endpoint per day, comparing a stable device under the legacy cadence with the new layer:

| | Collections/day | Uploads/day |
|---|---|---|
| Legacy inventory (5-min collect, 1-h force-resend) | 288 | 24 |
| New static sections (6-h collect, 24-h reconcile) | 4 | 1 |
| New posture sections (15-min collect, 1-h reconcile) | 96 | 24 |

Across 10,000 endpoints, moving static hardware from hourly to daily reconciliation removes roughly **230,000 uploads per day** of unchanged data.

**The larger scalability finding concerns the existing software pipeline.** It performs a full scan every 5 minutes — registry enumeration across every loaded user hive, `Get-AppxPackage -AllUsers`, `system_profiler SPApplicationsDataType` at 1.5–4 s, dpkg/rpm/snap/flatpak, browser-extension filesystem scans across all user homes, and batched `mdls` calls. That is 288 full scans per device per day, or about **2.9 million scans per day across 10,000 endpoints**, for data that changes a few times a week.

Compounding it: `hashSoftwareList` hashes `SoftwareInfo` wholesale **including `LastOpened`**, so a last-used timestamp change on any single application forces a full re-upload — unlike `hashServiceList`, which deliberately excludes volatile fields. Software therefore re-uploads far more often than the 1-hour force-resend implies.

Recommendation: raise the software collect interval to 6 hours with a 24-hour reconcile, and exclude `LastOpened` from the hash. Both are small and reversible, but they change a working pipeline, so they are recorded as approval-gated items in [06-existing-code-observations.md](06-existing-code-observations.md) rather than assumed here.

### Bandwidth

| Payload | Typical size |
|---|---|
| Legacy inventory | 100–300 KB |
| New static sections | 5–20 KB |
| Posture section | 10–40 KB |
| Health sample | 1–2 KB |
| Processes (250–350 procs, no cmdline) | 60–90 KB |
| Processes (450 procs with cmdline) | 250–300 KB |
| Certificates (200 certs) | 40–80 KB |

Compression is **implemented for the telemetry sender and shipped disabled** (`telemetry_gzip_enabled: false`), pending confirmation that the backend decompresses request bodies. The legacy inventory, software, services and audit-log paths remain uncompressed.

The benefit is measured, not estimated. One full collection cycle on a real Windows endpoint, over the 20 sections that host populated (`encryption` and `tpm` produced no data on it):

| | Raw | gzip | Saved |
|---|---|---|---|
| Whole cycle | 105,867 B | 18,007 B | **83.0%** |
| `processes` | 74,027 B | 10,232 B | 86.2% |
| `certificates` | 14,197 B | 2,946 B | 79.2% |
| `routes` | 6,947 B | 664 B | 90.4% |
| `persistence` | 4,653 B | 983 B | 78.9% |
| `network` | 2,098 B | 607 B | 71.1% |

The saving is entirely in the large sections. Small ones get **bigger** — `virtualization` went from 20 to 44 bytes and `firmware` from 59 to 80 — because the gzip header and trailer cost more than a short JSON object can recover. The sender therefore only compresses bodies of 1 KiB or more, and refuses any result that did not actually shrink.

### Resource limits

The scheduler already provides per-task startup jitter, a `Running` trylock preventing overlap, and a `recover()` wrapper per handler. The telemetry layer adds panic containment per collector, context cancellation, a bounded outbound queue, and a 900 KB per-message cap.

---

## 2. Privacy and security

### Not collected

Passwords, authentication tokens, credential material, browser history, cookies or saved passwords, document contents, messages, keystrokes, screenshots, clipboard contents. DLP is entirely out of scope.

### Specific decisions

| Data | Decision | Reason |
|---|---|---|
| **Process command lines** | Separate flag, **default off**; truncated to 512 bytes when enabled | Arguments routinely carry tokens, passwords and connection strings. Capability reports `disabled`, so the backend knows why the field is absent rather than assuming failure |
| **BitLocker/FileVault recovery keys** | Never transmitted | Availability and escrow *status* only. A key in a telemetry database is a key in a breach |
| **Wi-Fi passwords** | Never collected | SSID, BSSID and security type only |
| **Certificate private keys** | Never collected | Subject, issuer, thumbprint, validity, key usage only |
| **Error strings** | Classified into a fixed vocabulary | `os/exec` errors can carry stderr verbatim, including hostnames, paths and credentials |
| **Warnings** | Redacted and bounded | Credential-shaped pairs, long tokens and user home paths replaced with placeholders |
| **Fingerprint store** | No payload column | Hashes and timestamps suffice; persisting full inventory would keep a complete device profile on disk indefinitely |
| **Outbound queue** | Payloads only while in flight | Deleted on delivery, bounded by age, rows and bytes |
| **Routing tables, ARP** | Opt-in | Detailed telemetry, not basic inventory |

### Transport and at-rest

Transport is HTTPS with a bearer JWT plus the anon key, reusing the existing auth service including proactive refresh and the circuit breaker. Local state uses the existing SQLite stores in the config directory, hardened to 0700 with a SYSTEM/Admins-only DACL on Windows.

**Known weakness, out of scope:** `config.json` stores the access token, refresh token and agent secret in **plaintext**, protected only by filesystem ACLs. `process_flow.md` claims tokens are encrypted at rest via `EncryptSensitiveData()`; no such function exists. This is a real hardening gap, unrelated to telemetry, recorded in [06-existing-code-observations.md](06-existing-code-observations.md).

### RBAC and access auditing

Access control for telemetry lives in the backend via Supabase RLS and is outside this repository. The contract document flags which sections warrant stricter access: `sessions` and `processes` (user activity), `certificates` (security inventory), and `identity` (directory identifiers).

---

## 3. Backend compatibility

### Unchanged

Every existing endpoint, payload and field is untouched. `agent_enqueue_inventory`, `agent_enqueue_software`, `agent_enqueue_services` and `agent_enqueue_audit_logs` keep their exact shapes. With `telemetry_enabled=false` — the default — the agent's wire behaviour is byte-identical to today.

### Required backend work

| Phase | Requirement | Consequence if missing |
|---|---|---|
| **C** | Accept `agent_enqueue_telemetry` and **merge** the sections named in `Sections` | A partial payload would wipe unsent sections |
| **E** | Buffer chunked snapshots by `snapshot_id`, commit only when all `batch_count` batches arrive | Batch 0 committed, the rest discarded |
| **G** | Accept `agent_enqueue_telemetry_events` | Change events have nowhere to go |

Details and proposed DDL are in [../backend/telemetry-contracts.md](../backend/telemetry-contracts.md).

### Forward compatibility

Additive by construction: new sections are new keys, `section_versions` lets domains evolve independently, unknown fields are ignorable by older backends, and the capability manifest explains absent data without needing a schema change.

---

## 4. Roadmap

| Phase | Contents | Gate |
|---|---|---|
| **A** | Analysis docs, backend contract spec, `CLAUDE.md` correction | — |
| **B** | Telemetry foundation: envelope, section registry, capabilities, `CollectorResult`, error sanitization, collector interface, state store, bounded queue, chunking, health, event model, scheduler task, config | **Review of A/B before C** |
| **C — P0** | Device identity + VM detection, **directory join**, **sessions**, OS completeness, physical-disk/volume split, SMART, lightweight network | Backend merges `Sections` |
| **D — P1** | Per-volume encryption detail, strengthened patch inventory, screen-lock and password policy, privileged accounts | — |
| **E — P2** | Chunked domains: processes, certificates, persistence, detailed network. Browser classification from existing software inventory | Backend implements chunk assembly |
| **F — P3** | Battery detail, device health metrics, telemetry health surfacing | — |
| **G — P4** | Change events with priority routing | Backend accepts the events RPC |

Sessions and directory join sit in **P0** rather than later: they are core device context, and an inventory that cannot say who is logged in or whether a device is domain-joined is not an enterprise inventory.

Phases C–G ship independently and are individually revertible. Each is gated behind `telemetry_enabled` and its own capability flags, so a problematic collector can be switched off in configuration without a rollback.

### Definition of done, per phase

```
make quality-check && make format-check && make test && make verify-cross && make check-no-cgo && make build
```

Plus: new sections visible via the telemetry CLI on real hardware for each OS; `-telemetry-health` and `-capabilities` reporting sensibly; and the behavioural guards — fingerprint isolation, reconciliation timing, restart durability, chunking without truncation, queue eviction ordering, and privacy defaults — all green.
