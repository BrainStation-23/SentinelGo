# SentinelGo — Lockfile Module (`internal/lockfile`)

PID-file based single-instance guard. Prevents two copies of the
agent from running on the same host at the same time. Also auto-cleans
stale lockfiles left behind by crashed predecessors.

> **See also:** the call site inside the kardianos `Service` impl in
> [`cmd/sentinelgo/service.go`](../cmd/sentinelgo/service.go), and the
> startup step that runs the acquire in
> [`docs/08-project-overview.md`](08-project-overview.md#4-runtime-execution-flow).

## Public surface

| Symbol                              | Purpose                                                                 |
| ----------------------------------- | ----------------------------------------------------------------------- |
| `NewLockFile(name string)`          | Returns a `*LockFile` for `<default-dir>/<name>.lock`.                  |
| `NewLockFileWithPath(path string)`  | Returns a `*LockFile` at an exact path (used by tests).                 |
| `(*LockFile).TryAcquire() error`    | One-shot acquire. Returns `"lock already held by another process"` on conflict. |
| `(*LockFile).AcquireWithTimeout(d)` | Polls `TryAcquire` every 100 ms for up to `d`.                         |
| `(*LockFile).Release() error`       | Removes the lockfile and closes the underlying FD.                      |
| `(*LockFile).GetLockedPID() (int, error)` | Reads the PID from the lockfile.                                  |
| `(*LockFile).CheckExistingLock() (bool, error)` | Reports whether a live holder exists and cleans up stale ones. |
| `IsProcessRunning(pid int) bool`    | Platform-aware liveness check (see below).                             |

## Default lock directory

`NewLockFile(name)` picks the parent directory by `runtime.GOOS`:

| OS            | Directory                              |
| ------------- | -------------------------------------- |
| Windows       | `%USERPROFILE%\.sentinelgo\`           |
| Linux         | `/opt/sentinelgo/.sentinelgo/`         |
| macOS         | `/opt/sentinelgo/.sentinelgo/`         |
| (fallback)    | `$HOME/.sentinelgo/` or `/tmp`          |

The directory is created with mode `0750`. The `<name>.lock` file
itself is `0644` (so other processes can `read` the PID inside).

## Lockfile contents

Just the PID of the holder, followed by a newline:

```
12345
```

Written via `os.OpenFile(... O_CREATE|O_EXCL|O_RDWR, 0644)`. The
`O_EXCL` makes the create atomic on every supported OS — only the
process that wins the create gets the file. The PID is `fsync`'d
(`file.Sync()`) before `TryAcquire` returns, so a crash that kills
the agent right after the create cannot leave a PID-less lockfile
behind.

## Stale-lock detection

When `TryAcquire` sees an existing lockfile, it reads the PID and
asks `IsProcessRunning`:

- **Linux / macOS:** `process.Signal(syscall.Signal(0))` — a non-lethal
  probe that returns nil iff the PID is alive.
- **Windows:** `process.Signal(os.Kill)` — Windows has no real
  signal-zero equivalent; a successful `Kill` (which is a no-op the
  process can't actually catch from a Go process of our own) is
  taken to mean "alive", and the handle is `Release`d in a `defer`.

If the holder is dead, the stale lockfile is removed and the new
acquire proceeds.

## Stale-lock cleanup helper

`CheckExistingLock` is a read-only variant used by `-status` and the
installer: it reports whether a live lock exists, and (as a side
effect) deletes the lockfile if the recorded PID is dead. The
`cmd/sentinelgo` CLI uses this to decide whether `-install` should
bail out.

## Call site in this repo

The kardianos `Service` implementation in
[`cmd/sentinelgo/service.go`](../cmd/sentinelgo/service.go) embeds
`*lockfile.LockFile` as a field and calls `TryAcquire` inside its
`Start()`. That `Start()` is the third step of
`MainIntegration.Start()` — see
[`docs/08`](08-project-overview.md#4-runtime-execution-flow).

## What this module is not

- Not a distributed lock. It guards a single host only.
- Not a `flock(2)` / `LockFileEx` advisory lock. It's a pure
  PID-file. The acquire is best-effort: if the process crashes between
  the create and the `fsync`, the next start will see a 0-byte
  lockfile, treat the PID as `0`, the liveness probe will return
  false, and the stale file will be removed. There is no race in
  which two real agents can both hold the lock.
- Not a startup dependency. `cmd/sentinelgo` does not block forever
  on the lock — `TryAcquire` is the only call used in production.
