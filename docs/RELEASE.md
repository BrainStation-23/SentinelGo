# Release and versioning

## The problem this exists to prevent

A binary was found reporting itself as `v3.2.6-4-g40f52e7-dirty` while the
deployed version was `v3.2.8`. Three separate things had gone wrong at once:

1. **`-dirty`** — the build carried uncommitted local changes, so the artifact
   could not be rebuilt from any commit.
2. **`-4-g40f52e7`** — it was four commits past its base tag, and the updater's
   semver parser truncates at the first `-`, so it compared and reported as
   plain `3.2.6`.
3. **The base tag was stale.** `git describe` walks back to the newest tag
   *reachable from HEAD*. HEAD sat on a branch that did not contain `v3.2.7` or
   `v3.2.8`, so it reported a version **older than what production was already
   running** — exactly how a device accepts an "update" it has already passed,
   or reports a downgrade as current.

## The rule

- **Development builds** keep git-derived metadata. It is useful there.
- **A development build never self-updates.** `internal/version` classifies the
  version string, and the updater refuses to compare anything that is not a
  clean release version. It logs why and skips.
- **A release build requires an explicit, clean, tag-at-HEAD version.**
  `make release` will not run without one.

`sentinelgo -version` states which kind of build it is, so nobody has to
recognise the shape of `git describe` output to know what they are looking at:

```
SentinelGo version: v3.2.9
Build info: windows/amd64
Build type: release
```

```
SentinelGo version: v3.2.6-4-g40f52e7-dirty
Build info: windows/amd64
Build type: development (git-describe build 4 commit(s) past v3.2.6 with uncommitted changes)
Nearest reachable tag: v3.2.6
Note: development builds do not self-update.
```

## What counts as a release version

Accepted: `v3.2.9`, `3.2.9`, `v4.0.0-rc.1`

Rejected: `v3.2.6-4-g40f52e7-dirty`, `v3.2.8-dirty`, `dev`, `40f52e7`, `v3.2`,
`v3.2.8.1`, empty

## Recommended release procedure

Nothing below is automated. The agent never creates, moves or pushes a tag; the
gate only refuses to build something that would misrepresent itself.

```bash
# 1. Be on the commit you intend to release, with a clean tree.
git status --porcelain          # must be empty
git log -1 --oneline

# 2. Confirm the branch actually contains the newest existing tags, so the
#    version you are about to create is genuinely newer than what is deployed.
git tag --sort=-v:refname | head -5
git merge-base --is-ancestor "$(git tag --sort=-v:refname | head -1)" HEAD \
  && echo "HEAD contains the newest tag" \
  || echo "WARNING: HEAD does not contain the newest tag — check the branch"

# 3. Create the tag on that commit.
git tag -a v3.2.9 -m "v3.2.9"

# 4. Push it.
git push origin v3.2.9

# 5. Build. VERSION is mandatory; the gate checks the string, the working tree,
#    and that the tag points at HEAD.
make release VERSION=v3.2.9
```

The gate can be run on its own before committing to anything:

```bash
make verify-release-version VERSION=v3.2.9
# or directly:
go run ./scripts/checkversion -version v3.2.9 -require-clean-tree -require-tag-at-head
```

## Why the gate is written in Go

The Makefile is deliberately shell-agnostic so recipes work when GNU Make drives
them through `cmd.exe` on Windows. A `.sh` gate would silently not run there —
which is the environment where an accidental `-dirty` release is easiest to
produce. `scripts/checkversion` is a normal Go main package, invoked with
`go run`, and behaves identically on every platform.

## Development builds

Unchanged. `make build` still stamps `git describe --tags --always --dirty`, and
that binary works normally for everything except self-updating, which it
declines with a stated reason.

## Publishing the release to the backend

`get_latest_agent_release` is what tells fleet agents a new version exists.
Publishing a version there that no agent can verify (bad checksum, missing
signature) is caught by the updater's existing SHA-256 + ed25519 checks, which
run **before** anything is replaced. That path is unchanged.
