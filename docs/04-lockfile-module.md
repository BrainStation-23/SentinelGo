# SentinelGo — Lockfile Module (`internal/lockfile`)

Single-instance guard. Prevents two copies of the agent (service or `-run`,
any version) from running on the same host at the same time.

The lock is held by the operating system for as long as the lock file is
open, and the kernel releases it when the process exits for any reason:
service stop, self-update, `-stop`, kill, crash or power loss. A lock can
never be stale, so PID reuse can't keep the agent from starting (#242).

> **See also:** the call sites in
> [`cmd/sentinelgo/service/program.go`](../cmd/sentinelgo/service/program.go)
> (`Program.Start`) and
> [`cmd/sentinelgo/service/lifecycle.go`](../cmd/sentinelgo/service/lifecycle.go)
> (`RunForeground`).

## Public surface

| Symbol                             | Purpose                                                                 |
| ---------------------------------- | ----------------------------------------------------------------------- |
| `ErrAlreadyRunning`                | Returned (match with `errors.Is`) when another process holds the lock.  |
| `NewLockFile(name string)`         | Returns a `*LockFile` for `<lock dir>/<name>.lock`.                     |
| `NewLockFileWithPath(path string)` | Returns a `*LockFile` at an exact path (used by tests).                 |
| `(*LockFile).TryAcquire() error`   | Takes the lock without waiting. A no-op if this `LockFile` holds it.    |
| `(*LockFile).Release() error`      | Closes the file, which drops the lock. Leaves the file on disk.         |
| `(*LockFile).Path() string`        | The lock file's path, for messages.                                     |

The agent always uses the name `sentinelgo`, for the service and for `-run`.

## Lock directory

One fixed directory per OS, the same for every account:

| OS            | Lock file                                   |
| ------------- | ------------------------------------------- |
| Windows       | `C:\SentinelGo\.sentinelgo\sentinelgo.lock` |
| Linux / macOS | `/opt/sentinelgo/.sentinelgo/sentinelgo.lock` |

It is the directory that holds `config.json`. On Windows it used to be
`%USERPROFILE%\.sentinelgo`, which is
`C:\Windows\System32\config\systemprofile\.sentinelgo` for the service and the
admin's own profile for `-run`, so the two never saw each other's lock. A file
left at the old path is ignored and can be deleted.

The directory is restricted to SYSTEM and Administrators (root on Linux and
macOS), so a non-elevated `-run` can't take the lock. It can't read
`config.json` there either.

## How the lock is held

- **Windows:** `CreateFile` with `GENERIC_READ|GENERIC_WRITE`, share mode
  `FILE_SHARE_READ` and `OPEN_ALWAYS`. Any other attempt to open the file for
  writing gets `ERROR_SHARING_VIOLATION` (→ `ErrAlreadyRunning`) until the
  handle closes. Read-only openers can still read the PID. The handle isn't
  inheritable, so child processes (task scripts, the update `.bat`) can't keep
  the lock alive.
- **Linux / macOS:** `open(O_CREATE|O_RDWR, 0644)` and
  `flock(LOCK_EX|LOCK_NB)`. `EWOULDBLOCK` → `ErrAlreadyRunning`. Go opens files
  with `O_CLOEXEC`, so exec'd children don't inherit the descriptor.

Both use `golang.org/x/sys`; no cgo.

## Lockfile contents

After acquiring, the holder truncates the file and writes its PID followed by
a newline. The PID is for people and diagnostics only. Nothing reads it back to
decide whether an agent is running, and failing to write it doesn't fail the
acquire. Whatever an existing file contains (an old PID, garbage, nothing) is
overwritten.

## Why `Release` doesn't delete the file

On Unix, deleting the file would open a race: A unlinks it while B has the old
inode open and is waiting to lock it, then C creates a new file and locks it,
and B and C both believe they hold the lock. A leftover file is harmless
because its contents are never trusted.

## What this module is not

- Not a distributed lock. It guards a single host only.
- Not a startup dependency. `TryAcquire` never waits; a held lock makes
  `Program.Start` fail with service exit code 2 (see
  [`docs/06-service-module.md`](06-service-module.md#startup-failures-and-exit-codes)).
