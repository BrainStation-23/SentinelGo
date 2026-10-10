# Releasing SentinelGo

Releases are cut from `main`, built and signed by GitHub Actions, and published
as GitHub Releases. Their release notes are the version's section of
[`CHANGELOG.md`](CHANGELOG.md).

## Versioning

SentinelGo follows [Semantic Versioning](https://semver.org). Tags look like
`v3.4.0`:

- **Major** (`v4.0.0`): a change that needs action from people running the
  agent or the backend, such as a config field removed or an RPC contract changed.
- **Minor** (`v3.4.0`): new collectors, task handlers, CLI flags or other features.
- **Patch** (`v3.3.1`): bug and security fixes only.

## Steps

Every merged PR has already added its entry under `## [Unreleased]` in
`CHANGELOG.md`. Releasing turns those entries into the new version's section.

### 1. Trigger the release

Run **Trigger Release** (Actions → Trigger Release → Run workflow) on `main`:

- **bump**: `patch`, `minor` or `major`, counted from the latest release; or
- **version**: an explicit version such as `v3.4.0`.
- **dry run**: tick it to see the release notes in the run summary without
  opening a PR. Useful before the real run.

The workflow moves the `[Unreleased]` entries under `## [v3.4.0] - <today>`,
leaves an empty `[Unreleased]` above it, and opens a **Release v3.4.0** pull
request from `release/v3.4.0` with auto-merge turned on. It fails if
`[Unreleased]` is empty or the version is already tagged.

### 2. The release PR merges

The PR runs the same required checks as any other change, then merges itself.
Before it does, you can push edits to the `release/v3.4.0` branch to polish the
notes. They are exactly what users will read, so make sure every vulnerability
fix is listed under **Security** with its CVE or GHSA ID if one is published.

If another PR merges first and the release PR falls behind `main`, run Trigger
Release again with the same version. It rebuilds the branch from the current
`main`, including the newly merged entries.

### 3. The tag is pushed

When the release PR merges, **Tag Release**
([`.github/workflows/tag-release.yml`](.github/workflows/tag-release.yml)) sees
that the newest version in `CHANGELOG.md` has no tag and pushes `v3.4.0`.

You can also cut a release by hand: run
`make changelog-release VERSION=v3.4.0` on a branch and merge it in a PR. Tag
Release tags it the same way.

Both workflows authenticate with the `RELEASE_PAT` secret, because branches,
PRs and tags created with `GITHUB_TOKEN` don't trigger other workflows. The
token needs **Contents** and **Pull requests** read and write access on this
repository.

### 4. What the release workflow does

The tag push runs [`.github/workflows/release.yml`](.github/workflows/release.yml):

1. Runs the full CI pipeline (lint, security scans and tests on Linux, macOS and Windows).
2. Builds every target with `CGO_ENABLED=0` and the version injected via `-ldflags`.
3. Signs the binaries and installers with Ed25519 (`SENTINELGO_SIGNING_KEY`
   secret), writes `SHA256SUMS`, and generates `THIRD_PARTY_NOTICES.txt` and a
   CycloneDX SBOM per binary.
4. Creates build provenance and SBOM attestations.
5. Publishes the GitHub Release with the `[v3.4.0]` changelog section as its
   description, plus all of the artifacts below.

The backend syncs release assets from GitHub Releases, and agents pick up the
new version through the updater, which verifies the checksum and signature
before replacing itself.

## Release assets

| Asset | Notes |
|---|---|
| `sentinelgo-{linux,darwin}-{amd64,arm64}`, `sentinelgo-windows-amd64.exe` | Agent binaries |
| `*.sig` | Ed25519 signature for each binary and installer |
| `*.cdx.json` | CycloneDX SBOM for each binary |
| `SHA256SUMS` | Checksums for every binary and installer |
| `install.sh`, `install.command`, `install.bat`, `sentinelgo-install.desktop` | Installers. They verify the binary against `SHA256SUMS` before installing. |
| `THIRD_PARTY_NOTICES.txt` | Licenses of every linked dependency |
| `INSTALLATION.md` | Per-OS install guide |

## Building locally

```bash
make release VERSION=v3.4.0   # quality gate, cross-compile all targets, notices and SBOMs
make sign                     # needs SENTINELGO_SIGNING_KEY
```

Local builds are for testing only. Published releases always come from the
release workflow.

## Reproducing a release

Release binaries are reproducible: building the same tag with the same Go
version gives a bit-for-bit identical binary on any machine. Builds use
`-trimpath`, so no local file paths end up in the binary, and `CGO_ENABLED=0`,
so no system C toolchain is involved.

To check a published release yourself:

```bash
git clone https://github.com/BrainStation-23/SentinelGo.git
cd SentinelGo
git checkout vX.Y.Z
# Use the Go version from GO_VERSION in .github/workflows/release.yml
make all VERSION=vX.Y.Z

# Check your binaries against the published checksums
mkdir check && cp build/*/sentinelgo-* check/ && cd check
curl -sLO https://github.com/BrainStation-23/SentinelGo/releases/download/vX.Y.Z/SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

Build from a fresh clone with no local changes: Go records whether the working
tree was modified, and that flag is part of the binary.

Every binary should report `OK`. Releases up to and including v3.4.0 were
built before `-trimpath` was added; they embed the build machine's paths and
only reproduce on a GitHub Actions runner.

## If something goes wrong

- **Trigger Release says `[Unreleased]` is empty.** Nothing has changed since
  the last release that needs one, or PRs were merged with `skip-changelog`.
  Add entries in a PR first.
- **Trigger Release says `main` already has the section.** The release PR
  merged but no tag was pushed. Check the Tag Release run, fix the cause (for
  example an expired `RELEASE_PAT`), then run **Tag Release** manually.
- **The release PR doesn't merge.** A required check failed or the branch fell
  behind `main`. Fix the check, or run Trigger Release again with the same version.
- **The release workflow fails after tagging.** Fix the cause in a PR, delete
  the tag (`git push --delete origin vX.Y.Z`) and run **Tag Release** manually
  to tag `main` again. Or release the next patch version instead.
- **A published release is broken.** Don't move or reuse its tag. Release a new
  patch version with the fix, and describe the problem in that version's
  changelog section.
