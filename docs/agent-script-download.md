# How an agent downloads a command script

## TL;DR

1. Agent calls the `agent_get_tasks` RPC.
2. For each task, the response contains `scripts.<os>.path` — a path inside the **private** `command-scripts` storage bucket.
3. Agent calls `supabase.storage.from('command-scripts').download(path)` with its **normal session token**.
4. Storage RLS lets the download through because the path is referenced by a task assigned to that agent.

No signed URLs. No TTL window to miss. The agent can be offline for hours, days, or weeks; when it wakes up the file is still readable.

## Why we don't use signed URLs

Signed URLs expire. If `agent_get_tasks` mints a 10-minute URL and the agent is powered off when the task is assigned, by the time the PC boots the URL is dead and the agent has to round-trip back to the server to re-mint it. With per-task RLS, the agent just downloads — the database itself is the source of truth about who can read what.

## How RLS authorizes the download

The `command-scripts` bucket is private. Every read goes through `storage.objects` RLS.

We added a SECURITY DEFINER helper:

```sql
public.agent_can_read_command_script(p_path text) RETURNS boolean
```

It returns `true` iff there exists a row in `agent_command_tasks` where:
- `agent_id = auth.uid()` (the calling agent), AND
- some entry in `script_snapshot` has `path = p_path`.

The storage policy is then trivial:

```sql
CREATE POLICY "command-scripts agent select own tasks"
ON storage.objects
FOR SELECT TO authenticated
USING (
  bucket_id = 'command-scripts'
  AND public.agent_can_read_command_script(name)
);
```

Admins keep their full-access policy. Agents get exactly the files referenced by their own tasks — nothing more.

Status of the task does **not** matter. Queued, assigned, retrying, success, or failed — the file stays readable as long as the task row exists. Deleting the task row is what revokes access.

## Sequence

```text
Agent                          Postgres / PostgREST                     Storage
  |                                     |                                  |
  |--- rpc agent_get_tasks ------------>|                                  |
  |     (JWT: role=agent, sub=AGENT_ID) |                                  |
  |                                     |  flips queued -> assigned        |
  |<--- [{ command_id, scripts:{       |  for tasks of AGENT_ID           |
  |       linux:{path:"cmd/abc/run.sh",|                                  |
  |       size:1234 }}}, ...]           |                                  |
  |                                                                        |
  |--- GET /storage/v1/object/authenticated/command-scripts/cmd/abc/run.sh ->|
  |     (same JWT)                                                         |
  |                                                                        | RLS check:
  |                                                                        |   agent_can_read_command_script('cmd/abc/run.sh')
  |                                                                        |   -> EXISTS in agent_command_tasks where agent_id=AGENT_ID
  |                                                                        |      and snapshot has that path -> TRUE
  |<--- 200 OK + bytes ----------------------------------------------------|
```

## Sample task payload

```json
{
  "task_id": "f2b1...",
  "command_id": "9e44...",
  "command_slug": "rotate-logs",
  "status": "assigned",
  "scripts": {
    "linux":   { "path": "cmd/9e44/linux/run.sh",   "size": 842 },
    "darwin":  { "path": "cmd/9e44/darwin/run.sh",  "size": 842 },
    "windows": { "path": "cmd/9e44/windows/run.ps1","size": 1011 }
  },
  "payload": { "max_age_days": 7 }
}
```

Agent code (Go — matches the actual `internal/service/task/executor.go` download path):

```go
// task.Scripts is a JSON object keyed by OS: {"linux": {"path": "..."}, "windows": {"path": "..."}, "all": {"path": "..."}}
func downloadScript(ctx context.Context, cfg *config.Config, client *http.Client, task taskstore.Task, localPath string) error {
    entry, ok := task.Scripts[runtime.GOOS].(map[string]interface{})
    if !ok {
        // Optional fallback for scripts that target every OS
        entry, ok = task.Scripts["all"].(map[string]interface{})
        if !ok {
            return fmt.Errorf("no script found for platform: %s", runtime.GOOS)
        }
    }
    remotePath, _ := entry["path"].(string)
    if remotePath == "" {
        return fmt.Errorf("empty script path for platform: %s", runtime.GOOS)
    }

    url := fmt.Sprintf("%s/storage/v1/object/authenticated/command-scripts/%s", cfg.SupabaseURL, remotePath)
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
    if err != nil {
        return err
    }
    req.Header.Set("apikey", cfg.AccessToken)
    req.Header.Set("Authorization", "Bearer "+cfg.AccessToken)

    resp, err := client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        body, _ := io.ReadAll(resp.Body)
        // 403 = path not in any task assigned to this agent (stale or typo)
        return fmt.Errorf("storage download failed: status %d: %s", resp.StatusCode, string(body))
    }
    return os.WriteFile(localPath, mustReadAll(resp.Body), 0o600)
}
```

The agent reuses the same bearer token it obtained from `agent-login`; the storage policy above is what gates the read, not a separate signed URL.

## Error cases

| HTTP | Meaning | Likely cause |
|------|---------|--------------|
| 200 | OK | — |
| 401 | Bad/expired JWT | Re-login as the agent |
| 403 | RLS denied | Path is not in any task assigned to this agent. Usually a stale path the agent cached after the task was deleted, or a typo. Re-poll `agent_get_tasks`. |
| 404 | Object missing | Admin removed the file. Mark the task failed. |

## Integrity verification

The task payload includes `size` for each script entry. The agent should verify `bytes.length === entry.size` after download. We can later add an `sha256` field at upload time and verify that too — no schema change needed since `script_snapshot` is JSONB.

## Threat model

- **Agent A cannot download Agent B's scripts.** RLS proves the path is referenced by a task assigned to `auth.uid()`.
- **Compromised agent token** → attacker can download only the files referenced by tasks already assigned to that one agent.
- **Bucket stays private** at the row level. There are no public URLs and no signed URLs floating around.
- **Admins** still have full read/write via the existing `is_admin()` policy.

## Optional fallback (off by default)

The migration includes a commented-out policy that would let any account with the `agent` role read the entire bucket. Enable it only if the per-task policy ever blocks a legitimate download in production (e.g., a race we missed). Uncommenting that block widens the blast radius of a compromised agent token to "every script ever uploaded," so leave it off unless we have evidence we need it.

## Operational notes

- The helper function is `STABLE SECURITY DEFINER`, locked to `authenticated`, with `search_path = public` pinned. `EXECUTE` is revoked from `anon` and `PUBLIC`.
- Cost: the policy runs `EXISTS` over `agent_command_tasks` filtered by `agent_id` (indexed) and a `LATERAL jsonb_each` over the task's `script_snapshot`. A single agent has tens of tasks at most — this is microseconds. No GIN index needed.
- Admin upload flow is unchanged: admins write to the bucket via the existing admin policy.
