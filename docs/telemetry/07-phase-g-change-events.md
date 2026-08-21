# Phase G — Event-Driven State-Change Telemetry

Phase G reports **transitions**, not state. Phases B–F answer "what is this
device like right now"; Phase G answers "when did that change, and from what".

It is strictly additive. With `telemetry_events_enabled` false — the shipped
default — the agent behaves exactly as it did in Phase F: no watched state is
read or written, no events are produced, and nothing new is enqueued. The
feature gate is a nil `*telemetry.EventEngine` on the cycle service, not a flag
checked in a dozen places.

---

## 1. Why an event, not a smaller snapshot

A section snapshot cannot answer "when was BitLocker turned off on this
device". The section table holds current state and is overwritten; by the time
anyone asks, the evidence is gone. Making it answerable by keeping every
snapshot would mean storing the fleet's complete inventory once per cycle
forever.

An event is a dated, immutable assertion that one tracked value moved from A to
B. It is small, it is queryable, and it has its own retention (a year for
critical events, per the backend contract).

## 2. What it costs

Nothing measurable on a stable endpoint.

Phase G compares values the Phase B–F cycle **already collected**, exposed via
`CycleReport.Data`. It performs no collection of its own. Per cycle it costs one
JSON re-encode per watched section and one SQLite read plus a handful of small
writes. There are no extra WMI queries, no extra PowerShell, no extra
subprocesses, and nothing at all on the SCM startup path beyond one additive
schema migration.

## 3. The safety rule

> A collector error, timeout, permission denial, unsupported result, or an
> "unknown" value must never become an event, and must never overwrite the last
> known-good watched value.

This is the property the whole design is built around, because violating it
turns a broken query into a critical security page. Concretely:

| Situation | Behaviour |
|---|---|
| Collector returned `error` / `timeout` / `permission_denied` / `unsupported` | Watch skipped. Stored value untouched. |
| Collector returned `partial` | Watch skipped. A partial read of a set is indistinguishable from members having been removed. |
| Section absent from this cycle's data | Watch skipped. |
| Value is `""`, `unknown`, `not_present`, `none`, `n/a`, `unavailable` | Watch skipped. |
| Optional boolean absent from the payload | Watch skipped. Every optional boolean in these payloads is a pointer precisely so "could not determine" stays distinct from "no". |

Only `StatusSuccess` sections feed the diff engine.

## 4. First observation seeds, it does not alert

The first time a watch key is seen, its value is stored and **zero** events are
produced. Without this, enabling the feature across a fleet would fire a
`firewall_disabled` for every device that already had it off, plus a
`new_local_admin` for every existing administrator account, in the first cycle
after deployment — a synthetic incident on day one, burying any real finding.

The `-telemetry-cycle` command prints the seeded count explicitly, because "0
events" on a first run is the designed outcome and otherwise looks identical to
the feature being broken.

## 5. Watched values

Every watch resolves to a single scalar or a set of short identifiers. Nothing
watches a whole section.

| Watch key | Section | Kind |
|---|---|---|
| `security_protection.firewall.state` | `security_protection` | scalar |
| `security_protection.realtime_protection.state` | `security_protection` | scalar |
| `security_protection.tamper_protection.state` | `security_protection` | scalar |
| `secure_boot.state` | `secure_boot` | scalar |
| `encryption.protected_volumes` | `encryption` | membership |
| `security_posture.privileged_accounts` | `security_posture` | membership |
| `identity.hostname` | `identity` | scalar |
| `network.ipv4_addresses` | `network` | set summary |
| `directory.domain_joined` | `directory` | scalar |
| `directory.entra_joined` | `directory` | scalar |
| `os.pending_reboot` | `os` | scalar |
| `patches.installed` | `patches` | set summary |

**Membership** sets decompose into one present/absent watch per member, so
"alice was added" and "bob was added" in the same cycle are two events with
different ids, each with its own cooldown and flap history. A per-member row is
created only once that member has actually changed, so a device does not carry a
row per administrator account forever.

**Set summary** sets (patches, IP addresses) are too large or too churny for
per-member tracking. They produce one event per cycle carrying the count and a
bounded (10-entry) sample of what was added and removed.

## 6. Events implemented

### Critical — uploaded immediately, bypassing batching

| Event | Trigger |
|---|---|
| `firewall_disabled` | firewall state becomes `disabled` |
| `realtime_protection_disabled` | `enabled` → `disabled` |
| `tamper_protection_disabled` | `enabled` → `disabled` |
| `secure_boot_disabled` | `enabled` → `disabled` |
| `encryption_disabled` | a volume leaves the protected set |
| `new_local_admin` | an account joins the local administrative group |

A firewall going `enabled` → `partial` is **not** `firewall_disabled`. A host
that drops one profile of three is degraded, not unprotected, and treating that
as disabled would fire on every laptop whose active network profile changes.

### High — next flush, ahead of routine telemetry

| Event | Trigger |
|---|---|
| `firewall_restored` | `disabled` → `enabled` or `partial` |
| `realtime_protection_restored` | `disabled` → `enabled` |
| `tamper_protection_restored` | `disabled` → `enabled` |
| `secure_boot_restored` | `disabled` → `enabled` |
| `encryption_restored` | a volume rejoins the protected set |
| `directory_join_changed` | `domain_joined` changed |
| `entra_join_changed` | `entra_joined` changed |
| `watched_state_flapping` | a value crossed the flap threshold |

Restore events exist so **alert lifecycle stays entirely on the backend**.
Without a restore signal the backend can only close a `firewall_disabled` alert
by timeout or by hand — either alerts that linger after the fix or alerts that
close while the device is still exposed. The agent reports the transition;
what that does to an alert is the backend's decision.

### Normal — batched

| Event | Trigger |
|---|---|
| `hostname_changed` | hostname changed |
| `ip_changed` | routable IPv4 set changed |
| `reboot_required` | `pending_reboot` false → true |
| `os_update_installed` | a patch joined the installed set |

Loopback and link-local addresses are excluded from `ip_changed`: they are
identical on every device and never carry information about where it is.

### Deliberately silent

- Removing an administrator is **not** an event. Losing privilege is not an
  exposure, and firing on it would make every offboarding look like a security
  incident.
- `pending_reboot` true → false is **not** an event. A reboot clearing the flag
  is the expected resolution, not news.
- A patch leaving the installed set is **not** an event. It is usually a
  superseded update dropping off the list, not an uninstall.
- The first appearance of a newly-attached encrypted volume is silent (it is a
  baseline seed, not a restoration).

## 7. Blocked event types

These have a defined type in the backend contract but are **never emitted**,
because no reliable collector backs them in this build. They are recorded here
rather than wired to a guess.

| Event | Why blocked |
|---|---|
| `usb_connected`, `peripheral_changed` | No USB/peripheral telemetry collector. `peripherals.usb` reports `not_collected`. |
| `service_state_changed` | OS services are collected by the legacy `services-collect` pipeline, not by a telemetry section, so the change-detection layer has no section to diff. |
| `software_installed`, `software_removed` | Same: software inventory is on the legacy pipeline. |
| `antivirus_disabled` | The protection collector reports Defender's real-time protection, which is already covered by `realtime_protection_disabled`. A separate "an AV product was uninstalled" signal would need third-party product enumeration this build does not do. |
| `privileged_account_added` | The only privileged-group source collected is the LOCAL administrative group, which `new_local_admin` already reports. Emitting both would double-report one change; a distinct signal would need directory privileged-group membership. |

Unblocking any of these means shipping the collector first, then adding a watch.

## 8. Event identity and deduplication

```
event_id = sha256(device_id ‖ 0x00 ‖ event_type ‖ 0x00 ‖ watch_key ‖ 0x00 ‖ occurred_at)
```

The NUL separator means `("ab","c")` and `("a","bc")` cannot collide.

The id is computed once, at event construction, and serialised into the queued
payload. A delivery retry replays the stored bytes, so the backend sees an
`event_id` it already has and `on conflict (event_id) do nothing` drops the
duplicate. **No second deduplication database exists on the agent**, and none is
needed on the backend beyond that constraint.

`occurred_at` and `detected_at` are separate. For an immediate (critical/high)
event they are equal. For a debounced Normal event, `occurred_at` is when the
new value was **first seen** and `detected_at` is when it was confirmed —
otherwise every Normal event would be misdated by a full collection interval.

## 9. Debounce, cooldown and flapping

| Control | Default | Config key |
|---|---|---|
| Debounce | one successful cycle | `telemetry_event_debounce` (`0` = next cycle) |
| Cooldown | 10m | `telemetry_event_cooldown` |
| Flap window | 1h | `telemetry_event_flap_window` |
| Flap threshold | 4 | `telemetry_event_flap_threshold` |

**Debounce** applies to Normal events only. The first sighting of a new value
records a candidate; the next successful cycle confirms it. A value that changes
and reverts before confirmation produces **zero** events — the candidate is
discarded having never been reported. Critical and high events are never
debounced: waiting a cycle to report that the firewall went down would be the
wrong trade in the one case where latency matters.

**Cooldown** is per watch key. A suppressed event still commits its new value,
or the same transition would be rediscovered every cycle forever.

**Flapping** counts changes per key inside the window. On crossing the
threshold, individual events are replaced by a single `watched_state_flapping`
event for the rest of the window. A control toggling every cycle would otherwise
emit a critical event every cycle, and a storm of critical events buries every
other alert on the fleet.

All of this state is persisted, so it survives a restart. Flap counters that
reset on restart would let a crash-looping device evade suppression entirely.

Configuration is validated at startup and a bad value is **fatal to telemetry
startup**, not silently corrected: a cooldown longer than the flap window would
suppress events in a way nobody notices until an incident is missed.

## 10. Delivery

Events reuse the existing durable outbound queue, sender, authentication, retry
policy, dead-letter handling and `Flush()`. Nothing new was built.

| Class | RPC |
|---|---|
| `inventory`, `posture`, `health` | `agent_enqueue_telemetry` |
| `event` | `agent_enqueue_telemetry_events` |

Routing is decided from the message's stored `class` column, so a message queued
while offline still routes correctly after a restart.

**Event messages carry an empty section list.** The delivery path advances a
section's reconcile clock for every section a delivered message names; an event
message naming its source section would mark that section reconciled without the
backend ever having received it, and the section's real payload would then sit
unsent until its next content change — silent data loss with no error anywhere.
There is a second, explicit guard in `commitDelivered` that skips reconciliation
for `ClassEvent` regardless of what the row says.

Events are batched by priority (at most 50 per message) so the queue's priority
ordering stays meaningful and one backend rejection cannot dead-letter a whole
cycle's events.

Critical events are enqueued during the cycle and delivered by the `Flush()`
that the existing `telemetry-collect` handler already runs immediately
afterwards. If the backend is unreachable they stay durable in the same queue,
evicted last (eviction is lowest-priority-first).

## 11. Privacy

- Process command-line capture stays **off by default**
  (`processes_collect_cmdline`). No watch reads the `processes`, `certificates`
  or `sessions` sections, and a test asserts that.
- Certificate private keys are never read.
- No section payload appears in an event. `previous_value` and `current_value`
  are a closed struct with exactly six possible fields (`state`, `member`,
  `count`, `added`, `removed`, `changes`), and a table-driven allowlist test
  drives every watch through a real transition and fails on any field outside
  that set, on any nested object, and on any field added to the struct without
  updating the allowlist.
- Set deltas are capped at 10 sampled entries.
- Errors reaching the wire go through the existing `SanitizeError` vocabulary.
- The sender still never logs raw HTTP response bodies.

## 12. Storage

One new table, `telemetry_watched_state`, added as migration **v3** of the
existing telemetry state database (`sentinelgo_telemetry.db`). It is additive:
an agent that never enables the feature leaves it empty, and an existing
database gains it on first open with nothing else touched. Cold open with all
three migrations measures ~70 ms.

There is deliberately no payload column. A row holds one watched value — a
scalar, or one set member's present/absent flag — plus timestamps and the
debounce/cooldown/flap bookkeeping.

`sentinelgo -telemetry-reset` clears section reconciliation and the outbound
queue but **preserves** watched state, and says so. Re-sending inventory the
backend already has is harmless; forgetting the change-detection baseline means
anything that changes before the next cycle re-seeds it goes unreported.
