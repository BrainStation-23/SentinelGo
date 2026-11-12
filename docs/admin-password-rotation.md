# Local admin password rotation (Windows)

The agent rotates a local administrator account's password on a schedule and
after each use, and escrows every new password to the backend's vault before
it changes anything on the device (#361). Windows LAPS can't do this for us:
its `BackupDirectory` only backs up to Entra ID or Active Directory, never to
a third-party MDM.

Windows only for now. macOS and Linux may follow and would reuse the same
contract.

## Agent contract v1

Every call goes through `internal/supabase` with the agent's JWT, and is
wrapped in `auth.Service.DoWithAuthRetry`. Capability: **`admin_password_rotation_v1`**,
advertised by Windows agents only.

### 1. `agent_get_admin_password_policy(p_known_version text, p_status jsonb)`

The agent polls this every 15 minutes, and right away when it runs the
`admin-password-rotate` task. It reports its status on the same call, the same
way as `agent_get_dlp_policy` and `agent_get_yara_ruleset`.

Response:

```json
{
  "changed": true,
  "policy": {
    "version": "9f2c…",
    "enabled": true,
    "account": { "name": "" },
    "password": { "length": 24, "complexity": 4 },
    "rotate_every_days": 30,
    "post_use_delay_hours": 8
  },
  "rotate_after": "2026-11-12T09:30:00Z"
}
```

- `changed: false` (and no `policy`) when `p_known_version` is the current
  version. `version` is an opaque string. Any change to the policy must
  change it.
- `rotate_after` is **per device** and **always present** (`null` when there
  is no request), whether the policy changed or not. The agent rotates once
  `now >= rotate_after` if its last applied rotation is older than
  `rotate_after`. The server sets it:
  - to `revealed_at + post_use_delay_hours` when an admin reveals the
    password;
  - to `now()` when an admin presses **Rotate now**. The console also queues
    the `admin-password-rotate` task, so an online device acts within
    seconds.
- `policy.enabled: false` means do nothing: no rotations, and the agent
  reports `state: "disabled"`. The server returns `enabled: false` to agents
  without the capability, to agents outside the rollout, and when the org has
  the feature off.
- `account.name`: `""` means the built-in Administrator (RID 500, found by
  SID, so a renamed one is still found). Otherwise it is the name of an
  existing **local** account, at most 20 characters, matching
  `^[A-Za-z0-9._-]{1,20}$`. The agent never creates accounts in v1. If the
  account is missing, it reports `account_not_found`.
- `password.length` is 14–64 (default 24). `password.complexity` uses
  Windows LAPS' scale: 1 = upper case, 2 = upper + lower, 3 = + digits,
  4 = + symbols (default 4). Each password has at least one character from
  every class in its complexity. The agent clamps out-of-range values to
  the default.
- `rotate_every_days` is 1–365 (default 30). `post_use_delay_hours` is
  0–168 (default 8): how long after the account's last logon the agent
  rotates. 0 means right away.

`p_status` (at most 8 KB; the server answers `22023` if it is malformed):

```json
{
  "schema_version": 1,
  "state": "active",
  "managed_by": null,
  "account": { "name": "Administrator", "sid": "S-1-5-21-…-500", "builtin": true, "enabled": false },
  "last_rotation_id": "6c1d…",
  "last_rotated_at": "2026-11-01T10:00:00Z",
  "next_rotation_at": "2026-12-01T10:00:00Z",
  "pending_rotation_id": null,
  "last_error": null,
  "policy_version": "9f2c…"
}
```

- `state` is one of:
  - `active`
  - `disabled`: by the policy, or by the local kill switch
    `admin_password_rotation_enabled: false` in `config.json`
  - `managed_elsewhere`: see `managed_by`
  - `unsupported`: a domain controller, which has no local accounts, or an OS
    other than Windows
  - `error`: see `last_error`
- `managed_by` is `null`, `"windows_laps"` (the Windows LAPS CSP or Group
  Policy backs the password up to Entra ID or AD) or `"legacy_laps"`
  (Microsoft's AdmPwd LAPS). In either case the agent **stands down**: it
  makes no rotations and reports the state. It checks again on every tick.
- `last_error` is `{ "code": "…", "at": "…" }`. It **never** contains a
  password. The codes are `account_not_found`, `account_lookup_failed`, `password_policy` (the device's
  password rules rejected the new password), `set_failed`, `escrow_failed`,
  `confirm_failed` and `not_applied`.
- A status never carries the password or any part of it.

### 2. `agent_escrow_admin_password(p_payload jsonb)`

This is phase 1. The agent sends a newly generated password **before** it
sets it on the device:

```json
{
  "rotation_id": "6c1d0f3e-…",
  "account_name": "Administrator",
  "account_sid": "S-1-5-21-…-500",
  "password": "…",
  "reason": "scheduled",
  "generated_at": "2026-11-11T10:00:00Z"
}
```

- `rotation_id` is a UUID that the agent generates. The call is idempotent
  per `(agent, rotation_id)`: a retry with the same password returns success
  again. The same id with a different password is rejected with `22023`.
- `reason` is one of `initial`, `scheduled`, `post_use`, `requested`
  (reveal or Rotate now) and `account_changed`.
- The server stores the password in Supabase Vault (named
  `admin_password/<agent_id>/<rotation_id>`) as **pending**, and returns
  `{"accepted": true}`.
- Validation: the password is 14–64 printable ASCII characters,
  `account_sid` matches `^S-1-5-21(-[0-9]+){4}$`, `account_name` is at most
  256 characters and `rotation_id` is a UUID. Otherwise the server answers
  `22023`.
- A pending password can be revealed in the console as **"unconfirmed"**: if
  the device set it but went offline before confirming, it is the password
  that works.

### 3. `agent_confirm_admin_password(p_payload jsonb)`

This is phase 2, after the agent has tried to set the password:

```json
{ "rotation_id": "6c1d…", "state": "applied", "applied_at": "2026-11-11T10:00:02Z" }
{ "rotation_id": "6c1d…", "state": "failed",  "error_code": "password_policy" }
```

- `applied`: this rotation becomes **current**. The previous current one
  becomes **superseded**: the server keeps it for 30 days (it still works on
  a backup restored from before the rotation), then deletes it from Vault.
  Older pending rotations of the same agent are discarded.
- `failed`: the server deletes the pending row and its Vault secret.
- An unknown `rotation_id` gets `P0002`. The agent then drops its pending
  state.
- Idempotent: confirming a second time with the same state succeeds.

### 4. Native task `admin-password-rotate`

`{}` payload, capability `admin_password_rotation_v1`. The agent polls the
policy now and rotates if `rotate_after` (or the schedule) says so. The task
note is a one-line JSON result with `state`, `rotation_id`, `rotated` and
`error_code`, and **never** the password.

### 5. Console and backend (Compliance-OS)

- Permissions: `admin_passwords:view` (metadata) and
  `admin_passwords:retrieve` (dangerous: reveal or copy), the same as
  `bitlocker_keys`.
- Reveal RPC: shows the current password, plus an unconfirmed pending one if
  there is one. Each reveal writes an audit event and sets `rotate_after`.
- Metadata table: agent, rotation id, account name and SID, state
  (`pending | current | superseded | failed`), timestamps (escrowed,
  applied, revealed) and the vault secret id. The secret itself is never in a
  public table, task note or log.
- Policy settings in the console: org-level enable, account, length,
  complexity, interval and post-use delay. The device page shows the status
  (`managed_by`, last and next rotation, last error).

## Agent behaviour

1. Each tick (15 min): poll the policy and report the status. If the server
   doesn't have the RPC yet (404), the agent stays idle and reports nothing.
2. Stand down when the policy is disabled, the kill switch is off, Windows
   LAPS or legacy LAPS manages the password, or the device is a domain
   controller.
3. A rotation **left pending** by a crash or a failed confirm is settled
   first. The agent compares the account's password-last-set time with the
   moment it started setting the password. If the password changed after
   that, it confirms `applied`; otherwise it confirms `failed` with
   `not_applied`. The agent never keeps a password on disk.
4. A rotation is due when there is no applied rotation yet (`initial`), when
   `rotate_every_days` have passed (`scheduled`), when the account logged on
   after the last rotation and `post_use_delay_hours` have passed since that
   logon (`post_use`), when `rotate_after` has been reached (`requested`), or
   when the target account changed (`account_changed`).
5. To rotate, the agent:
   1. generates a password with `crypto/rand`;
   2. escrows it, and on failure stops: **the password on the device is
      unchanged**;
   3. saves the pending rotation id and start time (no secret);
   4. sets the password with `NetUserSetInfo` (level 1003; no command line,
      no PowerShell);
   5. confirms the result, and then clears the pending state.

   If the agent is offline, nothing rotates: escrow is the first step, so
   there is never a password the vault doesn't have.
6. After a failure, the agent waits an hour before trying again.
