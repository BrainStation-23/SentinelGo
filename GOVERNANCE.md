# Governance

This document describes who runs SentinelGo, how decisions are made, and how
the project keeps going if someone becomes unavailable.

## Roles

### Maintainer

SentinelGo currently has one maintainer:

| Name | GitHub | Areas |
|---|---|---|
| Tanimul Haque Khan | [@Warhammer4000](https://github.com/Warhammer4000) | Everything |

The maintainer:

- reviews and merges pull requests,
- triages issues and responds to bug reports and feature requests,
- handles vulnerability reports as described in [`SECURITY.md`](SECURITY.md),
- decides what goes into each release, and cuts releases as described in [`RELEASE.md`](RELEASE.md),
- has the final say on design and technical direction when there is no consensus.

The maintainer is listed in [`.github/CODEOWNERS`](.github/CODEOWNERS), so GitHub
asks for their review on every pull request.

### Contributors

Anyone who opens an issue, comments on a discussion, or submits a pull request
is a contributor. Contributors don't need any special access. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for how to contribute.

### Sponsor

[BrainStation-23](https://brainstation-23.com) sponsors the project and owns
the GitHub repository. Members of BrainStation-23's `internal-apps` team have
administrative access to the repository for continuity (see below). That access
on its own doesn't make someone a maintainer.

## How decisions are made

Decisions are made in the open, on GitHub:

- **Small changes** (bug fixes, new collectors, documentation) are proposed as a
  pull request and decided in its review.
- **Significant changes** start as an issue before any code is written. This
  covers anything that changes the backend contract, the config format, the
  update or signing process, or the platforms SentinelGo supports. Anyone can
  comment. The maintainer makes the decision and records it in the issue.
- **Disagreements** are resolved by discussion on the issue or pull request. If
  there's no consensus, the maintainer decides and explains why.

Every change reaches `main` through a pull request that passes the required
checks: builds, tests on Linux, macOS and Windows, security scanning and the
changelog check. No one can bypass this, administrators included.

## Becoming a maintainer

A contributor can become a maintainer after a sustained record of good
contributions, such as merged pull requests, reviews and helping in issues. The
existing maintainers nominate them, and the nomination is agreed in a GitHub
issue. New maintainers are added to the table above and to `CODEOWNERS`.

Once the project has two or more maintainers, the `main` branch ruleset will
require one approving review from a maintainer other than the author, in
addition to the checks above.

A maintainer can step down at any time by opening a pull request that removes
them from this file. A maintainer who has been inactive for six months may be
moved to emeritus status by the remaining maintainers or, if there are none,
by the sponsor.

## Continuity

The project must be able to keep going within a week if any one person becomes
unavailable.

- **Repository access.** BrainStation-23 organization owners and the
  `internal-apps` team have administrative access to the repository, so they
  can triage issues, merge pull requests and change settings without the
  maintainer.
- **Releases.** The signing key (`SENTINELGO_SIGNING_KEY`) is stored as a
  repository secret, so the release workflow can sign and publish a release
  regardless of who starts it. If the **Trigger Release** workflow's
  `RELEASE_PAT` stops working, any administrator can create a new token, or push
  the version tag directly to start the release.
- **New maintainer.** If the maintainer becomes unavailable, BrainStation-23
  appoints a successor and updates this file.

## Code of conduct

Everyone taking part in the project is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Changes to this document

Changes to governance are made by pull request and approved by the maintainers.
