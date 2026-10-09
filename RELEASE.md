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

### 1. Cut the changelog

Every merged PR has already added its entry under `## [Unreleased]`. Turn those
entries into the release's section and open a PR with the result:

```bash
git checkout -b release/v3.4.0 origin/main
make changelog-release VERSION=v3.4.0   # moves [Unreleased] under [v3.4.0] - <today>
git commit -am "Release v3.4.0"
git push -u origin release/v3.4.0       # open a PR against main
```

Review the section as release notes, since this is exactly what users will
read. Edit wording, merge duplicate entries, and confirm every vulnerability fix
is listed under **Security** with its CVE or GHSA ID if one is published. Then
get the PR approved and merge it.

### 2. Trigger the release

Run the **Trigger Release** workflow (Actions → Trigger Release → Run workflow)
with **version** set to the same `v3.4.0`. It checks that `CHANGELOG.md` on
`main` has a `[v3.4.0]` section, then pushes the tag. It refuses to tag a
version without one.

The workflow pushes the tag with the `RELEASE_PAT` secret so that the tag push
triggers the release workflow (pushes made with `GITHUB_TOKEN` don't).

### 3. What the release workflow does

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

## If something goes wrong

- **Trigger Release fails on the changelog check.** The `[vX.Y.Z]` section isn't
  on `main` yet. Merge the changelog PR from step 1, then rerun.
- **The release workflow fails.** Fix the cause in a PR, then delete the tag
  (`git push --delete origin vX.Y.Z`) and trigger the release again, or release
  the next patch version.
- **A published release is broken.** Don't move or reuse its tag. Release a new
  patch version with the fix, and describe the problem in that version's
  changelog section.
