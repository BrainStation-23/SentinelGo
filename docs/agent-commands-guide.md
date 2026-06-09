# Agent Commands Guide (curl)

How an agent **fetches** the work queued for it, **executes** the script(s), and **reports** the outcome back. For background on headers, the `apikey` vs `Authorization` distinction, and global error codes, see the **Supabase REST docs** for your project.

```
SUPABASE_URL = https://<your-project>.supabase.co
ANON_KEY     = <your-anon-jwt>
```

The `ANON_KEY` is the project's public anon JWT (role `anon`); pair it with the `apikey` and `Authorization: Bearer …` headers as required by Supabase PostgREST. The agent itself authenticates with the agent-issued bearer token from `internal/service/auth`, not the anon key.

All endpoints below live at:

```
POST {SUPABASE_URL}/rest/v1/rpc/{function_name}
```

Required headers on **every** request:

| Header | Value |
|---|---|
| `apikey` | The anon key above |
| `Authorization` | `Bearer <AGENT_JWT>` (from `agent-login`) |
| `Content-Type` | `application/json` |

> Identity (`agent_id`) is derived server-side from the JWT's `sub` claim. **Never** send `agent_id` in any of these payloads — it is ignored.

---

## 0. The lifecycle of a task

```text
                     admin clicks "Send command"
                                │
                                ▼
                ┌───────────────────────────────┐
                │  rpc: assign_command (admin)  │   row inserted in
                │  - snapshots payload + scripts│   agent_command_tasks
                │  - status = 'queued'          │   with frozen snapshot
                └───────────────┬───────────────┘
                                │
            agent polls ────────▼────────────────────────────────
                ┌───────────────────────────────┐
                │  rpc: agent_get_tasks         │   atomically flips every
                │  (caller = the agent)         │   queued row owned by this
                │  - returns claimed tasks      │   agent to 'assigned' and
                │  - sets status = 'assigned'   │   stamps assigned_at
                │  - bumps agents.last_seen     │
                └───────────────┬───────────────┘
                                │
              agent runs the script(s) locally
                                │
       ┌────────────────────────┼────────────────────────┐
       ▼                        ▼                        ▼
   success                   failed                  retrying
       │                        │                        │
       └────────────────────────┴────────────────────────┘
                                │
                                ▼
                ┌───────────────────────────────┐
                │  rpc: agent_update_task       │   updates status + note,
                │  (caller = the agent)         │   sets completed_at when
                │  - status: success/failed/    │   status is success/failed
                │            retrying           │   (retrying keeps it open)
                │  - note: optional free text   │
                └───────────────────────────────┘
```

### Status meanings

| Status | Set by | Meaning |
|---|---|---|
| `queued` | `assign_command` | Waiting for the agent's next poll. |
| `assigned` | `agent_get_tasks` | Agent has fetched it; execution in progress. |
| `success` | `agent_update_task` | Terminal. `completed_at` is set. |
| `failed` | `agent_update_task` | Terminal. `completed_at` is set. `note` should explain why. |
| `retrying` | `agent_update_task` | Non-terminal. Agent intends to try again and will call `agent_update_task` again later with `success` or `failed`. |
| `cancelled` | (admin, future) | Reserved. Agents should not act on cancelled tasks. |

### Snapshots (very important)

When the admin assigns a command, the server merges and **freezes** two things into the task row:

- `payload_snapshot` — `commands.payload` ⊕ OS-specific overrides for the agent's `os_type` ⊕ admin override at dispatch time. This is what your script should consume.
- `script_snapshot` — a copy of `commands.scripts` (a JSON object describing per-OS script files: `all`, `windows`, `darwin`, `linux`). Each entry typically contains a storage `path` (and possibly `name`, `mime`) inside the `command-scripts` Supabase Storage bucket.

Editing the underlying `commands` row **after** dispatch does NOT change in-flight tasks — they execute exactly the snapshot they were assigned.

---

## 1. `agent_get_tasks` — claim queued tasks

Atomically flips every `queued` task owned by `auth.uid()` to `assigned`, stamps `assigned_at`, refreshes `agents.last_seen`, and returns them with the joined command metadata.

- **Arguments:** none
- **Body:** `{}`
- **Idempotency:** Calling it again immediately returns `tasks: []` (the rows are now `assigned`, not `queued`). Each task is delivered to the agent **exactly once**.

### Request

```bash
curl --location 'https://<your-project>.supabase.co/rest/v1/rpc/agent_get_tasks' \
  --header 'apikey: <ANON_KEY>' \
  --header 'Authorization: Bearer <AGENT_JWT>' \
  --header 'Content-Type: application/json' \
  --data '{}'
```

### Response

```json
{
  "server_time": "2026-05-08T13:22:07.412+00:00",
  "tasks": [
    {
      "task_id": "9f1a2b3c-…",
      "command_id": "c0ffee00-…",
      "slug": "rotate-local-admin-password",
      "name": "Rotate local admin password",
      "description": "Generates a new password and updates the local admin account.",
      "category": "security",
      "tags": ["password", "hardening"],
      "payload":  { "rotation_days": 30, "length": 24 },
      "scripts":  {
        "all":     null,
        "windows": { "path": "commands/c0ffee00/windows.ps1", "name": "windows.ps1" },
        "darwin":  { "path": "commands/c0ffee00/darwin.sh",   "name": "darwin.sh"   },
        "linux":   null
      },
      "assigned_at": "2026-05-08T13:22:07.398+00:00",
      "created_at":  "2026-05-08T13:21:55.110+00:00"
    }
  ]
}
```

### Field reference

| Field | Notes |
|---|---|
| `task_id` | The ID you MUST send to `agent_update_task`. Treat as opaque. |
| `command_id` | The source command. Useful for logs/telemetry, not required to report. |
| `slug`, `name`, `description`, `category`, `tags` | Joined from `commands` at fetch time. May be `null` if the command was deleted (the snapshot still works). |
| `payload` | The frozen `payload_snapshot`. Always a JSON object — pass straight to the script (e.g. via env vars, stdin, or a temp file). |
| `scripts` | The frozen `script_snapshot`. Pick the entry matching the agent's OS, falling back to `all`. See **§3**. |
| `assigned_at` | Server timestamp when this poll claimed the row. |
| `created_at` | When the admin queued it. `assigned_at - created_at` = queue latency. |

### Polling guidance

- Poll at a fixed cadence (e.g. every 30–60s). On any 5xx, back off exponentially up to 5 attempts.
- Each poll also acts as a heartbeat (`last_seen` is bumped server-side).
- If you crash **after** a successful `agent_get_tasks` but **before** finishing execution, those tasks are now `assigned` and will NOT be re-delivered. Persist them locally as soon as you receive the response, before doing any work.

### Errors

| `code` | Meaning | Action |
|---|---|---|
| `42501` | `not authenticated` — bad/expired JWT, or service_role used as Bearer | Re-login |
| 5xx | Transient | Backoff + retry |

---

## 2. Resolving a script for the current OS

`scripts` in the response is a JSON object keyed by OS. Resolution algorithm:

1. Map your runtime to one of: `windows`, `darwin`, `linux`.
2. If `scripts[os]` is a non-null object → use it.
3. Else if `scripts.all` is a non-null object → use it (cross-platform PowerShell, bash, or whatever convention the admin has chosen).
4. Else → there is no script for this task. Report the task as `failed` with `note = "no script available for <os>"`.

A script entry typically looks like:

```json
{ "path": "commands/c0ffee00/windows.ps1", "name": "windows.ps1", "mime": "text/x-powershell" }
```

`path` is a key inside the **`command-scripts`** Supabase Storage bucket. To download it, request a signed URL via the Storage REST API using the agent's JWT:

```bash
curl --location 'https://<your-project>.supabase.co/storage/v1/object/sign/command-scripts/commands/c0ffee00/windows.ps1' \
  --header 'apikey: <ANON_KEY>' \
  --header 'Authorization: Bearer <AGENT_JWT>' \
  --header 'Content-Type: application/json' \
  --data '{ "expiresIn": 600 }'
```

Response:

```json
{ "signedURL": "/object/sign/command-scripts/commands/c0ffee00/windows.ps1?token=…" }
```

Prefix it with `{SUPABASE_URL}/storage/v1` and `GET` (no auth headers needed on the signed URL itself):

```bash
curl --location "https://<your-project>.supabase.co/storage/v1/object/sign/command-scripts/commands/c0ffee00/windows.ps1?token=…" \
  --output script.ps1
```

If the signed-URL request returns 403 / 404, the bucket policy may not allow agents to mint signed URLs. In that case fall back to the authenticated download:

```bash
curl --location 'https://<your-project>.supabase.co/storage/v1/object/authenticated/command-scripts/commands/c0ffee00/windows.ps1' \
  --header 'apikey: <ANON_KEY>' \
  --header 'Authorization: Bearer <AGENT_JWT>' \
  --output script.ps1
```

### Passing the payload to the script

There is no enforced convention. Common choices:

- Write `payload` to a temp file and pass its path as `--payload-json /tmp/x.json`.
- Pipe `payload` into the script's stdin.
- Flatten primitive fields into env vars (e.g. `ROTATION_DAYS=30`).

Pick one and document it on the admin side so script authors know what to expect.

---

## 3. `agent_update_task` — report progress / completion

Updates one task that **belongs to this agent** (`agent_id = auth.uid()`).

- **Arguments:** `p_task_id uuid`, `p_status text`, `p_note text` (optional).
- **Body:** named-arg style — top-level keys map to function args.
- **Allowed statuses:** `success`, `failed`, `retrying`. Anything else → `22023`.
- **Side effects:**
  - `success` / `failed` → sets `completed_at = now()`, `updated_at = now()`.
  - `retrying` → leaves `completed_at` untouched; `updated_at = now()`.
  - In all three cases `agents.last_seen` is bumped.
- **`note` semantics:** `coalesce(p_note, existing)`. Sending `null` (or omitting it) keeps the previous note; sending an empty string overwrites with empty. To clear it, send `""`.

### 3a. Success

```bash
curl --location 'https://<your-project>.supabase.co/rest/v1/rpc/agent_update_task' \
  --header 'apikey: <ANON_KEY>' \
  --header 'Authorization: Bearer <AGENT_JWT>' \
  --header 'Content-Type: application/json' \
  --data '{
    "p_task_id": "9f1a2b3c-1111-2222-3333-444455556666",
    "p_status":  "success",
    "p_note":    "Rotated. New hash stored in vault entry abc123."
  }'
```

### 3b. Failure (with diagnostic)

```bash
curl --location 'https://<your-project>.supabase.co/rest/v1/rpc/agent_update_task' \
  --header 'apikey: <ANON_KEY>' \
  --header 'Authorization: Bearer <AGENT_JWT>' \
  --header 'Content-Type: application/json' \
  --data '{
    "p_task_id": "9f1a2b3c-1111-2222-3333-444455556666",
    "p_status":  "failed",
    "p_note":    "exit=1 stderr=\"Access denied: SeServiceLogonRight required\""
  }'
```

> Keep `note` short and human-readable (a few hundred chars). For full logs, ship them via `agent_insert_audit_log` / `agent_insert_audit_logs_batch` and reference the log ID in the note if useful.

### 3c. Retrying (intermediate, non-terminal)

Use when the agent intends to try the same task again — e.g. after a transient network failure or a reboot is required.

```bash
curl --location 'https://<your-project>.supabase.co/rest/v1/rpc/agent_update_task' \
  --header 'apikey: <ANON_KEY>' \
  --header 'Authorization: Bearer <AGENT_JWT>' \
  --header 'Content-Type: application/json' \
  --data '{
    "p_task_id": "9f1a2b3c-1111-2222-3333-444455556666",
    "p_status":  "retrying",
    "p_note":    "Reboot pending; will resume after next boot. Attempt 2/5."
  }'
```

A `retrying` task stays open. The agent is expected to call `agent_update_task` on it again later with a terminal status (`success` / `failed`). The server does NOT auto-flip it back to `queued`, and `agent_get_tasks` will NOT return it again — the agent owns the retry loop entirely.

### Response (all three cases)

```json
{
  "success": true,
  "task": {
    "id": "9f1a2b3c-…",
    "command_id": "c0ffee00-…",
    "agent_id":   "<your-agent-uuid>",
    "status":     "success",
    "note":       "Rotated. New hash stored in vault entry abc123.",
    "payload_snapshot": { … },
    "script_snapshot":  { … },
    "assigned_at":  "2026-05-08T13:22:07.398+00:00",
    "completed_at": "2026-05-08T13:22:41.902+00:00",
    "created_at":   "2026-05-08T13:21:55.110+00:00",
    "updated_at":   "2026-05-08T13:22:41.902+00:00",
    "created_by":   "<admin-uuid>"
  }
}
```

### Errors

| `code` | Meaning | Action |
|---|---|---|
| `42501` | `not authenticated` | Re-login |
| `22023` | `status must be success, failed, or retrying` | Fix payload, do not retry |
| `P0002` | `task not found` — wrong `task_id`, OR the task belongs to another agent | Drop it, do not retry |
| 5xx | Transient | Backoff + retry; safe because update is idempotent for the same `(task_id, status, note)` |

---

## 4. End-to-end example

```bash
# 1. Claim everything that's queued for me.
TASKS=$(curl -s -X POST \
  "$SUPABASE_URL/rest/v1/rpc/agent_get_tasks" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" -d '{}')

# 2. For each task, pick the right script for my OS, run it, capture exit code + stderr.
echo "$TASKS" | jq -c '.tasks[]' | while read -r T; do
  TASK_ID=$(echo "$T" | jq -r .task_id)
  PAYLOAD=$(echo "$T" | jq -c .payload)
  SCRIPT_PATH=$(echo "$T" | jq -r '.scripts.linux.path // .scripts.all.path // empty')

  if [ -z "$SCRIPT_PATH" ]; then
    curl -s -X POST "$SUPABASE_URL/rest/v1/rpc/agent_update_task" \
      -H "apikey: $ANON_KEY" -H "Authorization: Bearer $JWT" \
      -H "Content-Type: application/json" \
      -d "{\"p_task_id\":\"$TASK_ID\",\"p_status\":\"failed\",\"p_note\":\"no script for linux\"}"
    continue
  fi

  # download the script (signed URL flow omitted for brevity) → /tmp/run.sh
  echo "$PAYLOAD" > /tmp/payload.json
  if bash /tmp/run.sh --payload-json /tmp/payload.json 2>/tmp/err; then
    NOTE="ok"
    STATUS="success"
  else
    NOTE=$(head -c 400 /tmp/err)
    STATUS="failed"
  fi

  curl -s -X POST "$SUPABASE_URL/rest/v1/rpc/agent_update_task" \
    -H "apikey: $ANON_KEY" -H "Authorization: Bearer $JWT" \
    -H "Content-Type: application/json" \
    -d "$(jq -n --arg id "$TASK_ID" --arg s "$STATUS" --arg n "$NOTE" \
            '{p_task_id:$id, p_status:$s, p_note:$n}')"
done
```

---

## 5. FAQ / gotchas

- **`agent_get_tasks` returned 0 tasks but the admin says they queued one.** The previous poll already claimed it. Look for it in your local store with status `assigned`.
- **`P0002 task not found` when reporting.** Either you typed the wrong `task_id`, or this JWT is for a different agent. Tasks can only be updated by their owner.
- **Re-running a `failed` task.** There is no "re-queue" RPC for agents. The admin must dispatch the command again, which produces a brand-new `task_id`.
- **Editing `commands` after dispatch.** Doesn't affect in-flight tasks. Each task carries its own `payload_snapshot` and `script_snapshot`.
- **`apikey` vs `Authorization` mix-up.** `apikey` is the public anon key; `Authorization` is the agent JWT. Swapping them yields `42501 not authenticated` or `401 Invalid API key`.
- **Time fields.** All timestamps are UTC ISO-8601. `assigned_at - created_at` gives queue latency; `completed_at - assigned_at` gives execution time.
