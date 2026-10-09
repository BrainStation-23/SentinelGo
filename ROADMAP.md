# Roadmap

What we intend to work on next. It's a statement of direction, not a promise
of dates, and it changes as priorities do. Each item links to an issue once
there is one; comment there if something matters to you, or open a
[feature request](https://github.com/BrainStation-23/SentinelGo/issues/new?template=feature_request.yml).

Last reviewed: October 2026. The maintainer reviews this file at least every
three months, and at every minor release.

## Now (next 1–2 releases)

- **Finish the Supabase client consolidation** ([#87](https://github.com/BrainStation-23/SentinelGo/issues/87)).
  The `internal/supabase` client shipped in v3.3.0. What remains is verifying
  gateway authentication and error behaviour on staging ([#88](https://github.com/BrainStation-23/SentinelGo/issues/88)).
- **OpenSSF Best Practices silver badge.** Done so far: changelog-based release
  notes, governance, reproducible builds, the race detector in CI and the
  [assurance case](docs/assurance-case.md). Remaining: DCO sign-off on commits.

## Next (within about 6 months)

- **Automatic rollback when an update fails to start.** A failed binary replace
  already rolls back; an update that installs but then won't start should too.
- **Keep agent credentials in the OS credential store.** Today the agent secret
  and tokens sit in `config.json`, protected by file permissions. Use the Windows
  credential APIs and the macOS Keychain where that can be done without cgo.
- **Signed release tags**, so the source of a release can be verified as well
  as its binaries.
- **Test coverage to 90%** (currently about 82%).

## Later

- **A second maintainer.** Then the `main` branch ruleset goes back to requiring
  an approving review from someone other than the author (see
  [`GOVERNANCE.md`](GOVERNANCE.md)).
- **An independent security review** of the agent, the updater and the release
  pipeline.
- **SPDX license and copyright headers** in every source file.

## Recently done

See [`CHANGELOG.md`](CHANGELOG.md) for everything that has shipped.
