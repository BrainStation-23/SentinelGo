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

Every merged PR has already added its entry as a fragment file in
[`changelog.d/`](changelog.d/README.md). Releasing folds those fragments into
the new version's section of `CHANGELOG.md` and deletes them.

### 1. Trigger the release

Run **Trigger Release** (Actions → Trigger Release → Run workflow) on `main`:

- **bump**: `patch`, `minor` or `major`, counted from the latest release; or
- **version**: an explicit version such as `v3.4.0`.
- **dry run**: tick it to see the release notes in the run summary without
  opening a PR. Useful before the real run.

The workflow folds the fragments in `changelog.d/` under `## [v3.4.0] - <today>`
(grouped as Added, Changed, Deprecated, Removed, Fixed, Security, each group in
file-name order), deletes them, leaves an empty `[Unreleased]` above it, and
opens a **Release v3.4.0** pull request from `release/v3.4.0` with auto-merge
turned on. It fails if there are no fragments or the version is already tagged.

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
It then opens a `main` -> `dev` pull request with auto-merge on, so `dev` picks
up the `[v3.4.0]` section and drops the fragments it released. Let it merge
(with a merge commit) before the next `dev` -> `main` PR. Otherwise that PR
brings the released fragments back.

You can also cut a release by hand: run
`make changelog-release VERSION=v3.4.0` on a branch and merge it in a PR. Tag
Release tags it the same way.

Both workflows authenticate with the `RELEASE_PAT` secret, because branches,
PRs and tags created with `GITHUB_TOKEN` don't trigger other workflows. The
token needs **Contents** and **Pull requests** read and write access on this
repository.

### 4. What the release workflow does

The tag push runs [`.github/workflows/release.yml`](.github/workflows/release.yml):

1. Waits for the **CI passed** check on the tagged commit. The push to `main`
   that the tag came from runs CI on that exact commit, after its pull request
   already passed lint, security scans and tests on Linux, macOS and Windows.
   The release stops if CI didn't pass, so nothing is built from an untested
   commit.
2. Builds every target with `CGO_ENABLED=0` and the version injected via `-ldflags`,
   using the Go version from `go.mod`'s `toolchain` line.
3. Scans every built binary with `govulncheck -mode=binary`. Any reachable
   vulnerability, in the Go toolchain or a dependency, stops the release before
   anything is signed.
4. Code-signs the two macOS binaries if the `MACOS_CODESIGN_P12` secret is
   set (see [macOS code signing](#macos-code-signing)). Without it they ship
   unsigned, as before.
5. Signs the binaries and installers with Ed25519 (`SENTINELGO_SIGNING_KEY`
   secret), writes `SHA256SUMS`, and generates `THIRD_PARTY_NOTICES.txt` and a
   CycloneDX SBOM per binary. These cover the code-signed macOS binaries.
6. Creates build provenance and SBOM attestations.
7. Publishes the GitHub Release with the `[v3.4.0]` changelog section as its
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

## macOS code signing

MDM profiles that give the agent permissions on a Mac (Full Disk Access,
notifications) identify it by its code signature. An ad-hoc signature changes
with every build, so those profiles need a certificate signature that stays the
same across releases (#352).

For now the certificate comes from our own internal CA, not Apple. MDM
installs the CA's root certificate on managed Macs. Notarization doesn't
apply: it needs a Developer ID certificate, and Gatekeeper only checks it on
downloads that carry the quarantine flag, which MDM installs and `curl` don't
set. A Developer ID Application certificate can replace the internal one
later through the same secrets.

| Secret | Value |
|---|---|
| `MACOS_CODESIGN_P12` | Base64 of a `.p12` holding the code-signing certificate (extended key usage `codeSigning`), its private key and the CA certificates above it |
| `MACOS_CODESIGN_P12_PASSWORD` | The `.p12`'s password |

If `MACOS_CODESIGN_P12` is set, the sign job runs on a macOS runner and
[`scripts/macos-codesign.sh`](scripts/macos-codesign.sh) signs both macOS
binaries. It uses the identifier `com.sentinelgo.agent` and the hardened
runtime, and logs each binary's designated requirement. If it isn't set, the
job runs on Linux, the release logs a warning, and the macOS binaries ship
unsigned. Either way the release goes out.

On the Mac, `install.sh`, `sentinelgo -install` and the updater keep a
certificate signature that still verifies. They sign a binary ad-hoc only when
it has no such signature, because an ad-hoc signature would replace it.

To make a certificate from an internal CA with OpenSSL (key and CA handling
are up to the CA's owner):

```bash
openssl req -new -newkey rsa:3072 -nodes -keyout codesign.key \
  -subj "/CN=SentinelGo Code Signing/O=BrainStation-23" -out codesign.csr
# Sign the CSR with the CA and these extensions:
#   keyUsage = critical, digitalSignature
#   extendedKeyUsage = critical, codeSigning
#   basicConstraints = critical, CA:FALSE
openssl pkcs12 -export -legacy -inkey codesign.key -in codesign.crt \
  -certfile ca-chain.pem -out codesign.p12
base64 < codesign.p12 | gh secret set MACOS_CODESIGN_P12
gh secret set MACOS_CODESIGN_P12_PASSWORD
```

`-legacy` (OpenSSL 3) writes encryption that macOS's `security import`
accepts. Keep the same certificate, or at least the same CA and subject, for
as long as profiles pin it. A new certificate changes the designated
requirement, and every profile built from the old one has to be rebuilt.

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

Every binary should report `OK`, except the macOS binaries of a release that
was code-signed in CI (#352): the signature is added after the build, so
those differ from a rebuild by their code signature. Releases up to and including v3.4.0 were
built before `-trimpath` was added; they embed the build machine's paths and
only reproduce on a GitHub Actions runner.

## If something goes wrong

- **Trigger Release says there is nothing to release.** `changelog.d/` has no
  fragments: nothing has changed since the last release that needs one, or PRs
  were merged with `skip-changelog`. Add fragments in a PR first.
- **Trigger Release says `main` already has the section.** The release PR
  merged but no tag was pushed. Check the Tag Release run, fix the cause (for
  example an expired `RELEASE_PAT`), then run **Tag Release** manually.
- **The release PR doesn't merge.** A required check failed or the branch fell
  behind `main`. Fix the check, or run Trigger Release again with the same version.
- **The govulncheck scan of the release binaries fails.** A Go or dependency
  version in the release has a known vulnerability the agent can reach. The
  public log shows only how many: build the release locally (`make all`) and
  run `govulncheck -mode=binary` on a binary to see which ones and the
  versions that fix them. Bump the `toolchain` line
  in `go.mod` or the dependency in a PR, delete the tag and run **Tag Release**
  again, or release the next patch version.
- **Verify CI passed fails.** CI on the tagged commit failed or never ran. If
  the failure was flaky, re-run the failed CI jobs on `main`, then re-run the
  release workflow. Otherwise fix it in a PR and release the next version.
- **The release workflow fails after tagging.** Fix the cause in a PR, delete
  the tag (`git push --delete origin vX.Y.Z`) and run **Tag Release** manually
  to tag `main` again. Or release the next patch version instead.
- **A published release is broken.** Don't move or reuse its tag. Release a new
  patch version with the fix, and describe the problem in that version's
  changelog section.
