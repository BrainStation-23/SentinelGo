# Contributing to SentinelGo

Thank you for taking the time to contribute! Every bug report, feature idea, documentation fix, and code improvement makes SentinelGo better for everyone.

---

## Table of contents

- [Code of Conduct](#code-of-conduct)
- [Ways to contribute](#ways-to-contribute)
- [Getting started](#getting-started)
- [Development workflow](#development-workflow)
- [Commit style](#commit-style)
- [Coding standards](#coding-standards)
- [Changelog entries](#changelog-entries)
- [Pull request checklist](#pull-request-checklist)
- [Code review](#code-review)
- [Reporting bugs](#reporting-bugs)
- [Suggesting features](#suggesting-features)
- [Cross-platform rules](#cross-platform-rules)
- [Questions](#questions)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).
By participating you agree to uphold it.

---

## Ways to contribute

| Type | How |
|---|---|
| 🐛 Bug report | Open a [Bug Report issue](https://github.com/BrainStation-23/SentinelGo/issues/new?template=bug_report.yml) |
| 💡 Feature request | Open a [Feature Request issue](https://github.com/BrainStation-23/SentinelGo/issues/new?template=feature_request.yml) |
| 🔐 Security vulnerability | See [SECURITY.md](SECURITY.md) — do **not** open a public issue |
| 📝 Docs improvement | Edit any `.md` file and open a PR |
| 🛠️ Code fix or feature | Fork → branch → PR (see workflow below) |

---

## Getting started

**Prerequisites**

- Go 1.26+
- `make` (GNU Make)
- Git

**Clone and build**

```bash
git clone https://github.com/BrainStation-23/SentinelGo.git
cd SentinelGo
cp .env.example .env        # fill in your Supabase credentials
make build                  # produces bin/sentinelgo[.exe]
make test                   # run the test suite
```

**Verify cross-platform types check clean**

```bash
make verify-cross           # type-checks linux/darwin/windows in one pass
```

**Fuzzing**

Parsers that handle input the agent doesn't control (log lines, extension manifests, EDID blobs, version strings, signatures) have Go fuzz targets (`func FuzzXxx(f *testing.F)` in `*_fuzz_test.go`). Their seed corpora run as ordinary tests under `make test`. To actually fuzz them:

```bash
make fuzz-list                               # targets that build on this OS
make fuzz                                    # fuzz each target for 30s, one at a time
make fuzz FUZZTIME=5m FUZZ_RUN=EDID          # longer, and only targets matching a regexp
```

CI fuzzes every target nightly (`.github/workflows/fuzz.yml`). When a target fails, Go writes the input to `testdata/fuzz/<FuzzName>/`. Commit that file together with the fix so it stays as a regression seed. New parsers of untrusted input should come with a fuzz target.

---

## Development workflow

1. **Fork** the repository and clone your fork.
2. **Create a branch** off `main` with a descriptive name:
   ```bash
   git checkout -b fix/audit-log-parse-crash
   git checkout -b feat/rollback-on-update-failure
   ```
3. **Make your changes.** Keep each commit focused on one thing.
4. **Run checks locally** before pushing:
   ```bash
   make test
   make verify-cross
   make check-no-cgo
   gofmt -s -l .             # should print nothing
   go vet ./...
   ```
5. **Push** your branch and open a pull request against `main`.

---

## Commit style

We use [Conventional Commits](https://www.conventionalcommits.org):

```
<type>(<scope>): <short summary>

[optional body]

[optional footer]
```

| Type | When to use |
|---|---|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Code change that is neither a fix nor a feature |
| `test` | Adding or fixing tests |
| `chore` | Build, CI, dependency updates |
| `perf` | Performance improvement |

Examples:
```
feat(auditlogs): add journald cursor persistence across restarts
fix(updater): handle missing asset for windows-arm64 gracefully
docs(readme): add devicon platform icons
chore(ci): pin golangci-lint to v2.12.2
```

---

## Coding standards

SentinelGo follows the standard Go style guides. Contributions are expected to comply with them:

- [Effective Go](https://go.dev/doc/effective_go)
- [Go Code Review Comments](https://go.dev/wiki/CodeReviewComments)
- [Go Doc Comments](https://go.dev/doc/comment) for package, type and function documentation

On top of those, the project rules in [Cross-platform rules](#cross-platform-rules) apply, plus these:

- Handle every error explicitly. This is a long-running service, so don't panic and don't silently drop errors.
- Run external programs through `internal/binpath` (absolute paths, never a bare name), and pass values as separate arguments. If a value has to go into a PowerShell script, quote it with `shared.PSQuote`.
- All Supabase access goes through `internal/supabase`; read and write tokens only through `cfg.GetAccessToken` / `GetRefreshToken` / `SetTokens`.
- New parsers of input the agent doesn't control come with a fuzz target.

**Enforcement.** CI checks formatting with `gofmt -s` and runs `go vet` and `golangci-lint` on Linux, macOS and Windows; any finding fails the build. Run `make format-check` and `make quality-check` locally before pushing.

---

## Changelog entries

[`CHANGELOG.md`](CHANGELOG.md) is the project's release notes: each release's section is published as its GitHub release description. Every pull request with a user-visible change adds a line under `## [Unreleased]`, in the matching group:

| Group | For |
|---|---|
| `### Added` | New features, collectors, CLI flags, task handlers |
| `### Changed` | Changes to existing behaviour or output |
| `### Deprecated` | Features that will be removed in a later release |
| `### Removed` | Features or files that are gone |
| `### Fixed` | Bug fixes |
| `### Security` | Vulnerability fixes and hardening. Include the CVE or GHSA ID once one is published. |

Write for someone running the agent, not for reviewers: say what changed for them, not which functions moved. For example, `- Updater: a binary that fails its checksum is deleted instead of left on disk.`

If a PR has nothing to tell users (tests, CI, refactors, docs), label it `skip-changelog`. Dependabot PRs (`dependencies` label) are exempt automatically. The **Changelog** check enforces this and validates the file's format; run `make changelog-check` locally.

---

## Pull request checklist

Before marking your PR ready for review, confirm:

- [ ] `make test` passes on your machine
- [ ] `make verify-cross` passes (no type errors on any OS)
- [ ] `make check-no-cgo` passes (no `import "C"` introduced)
- [ ] `gofmt -s -l .` prints nothing (all files formatted)
- [ ] New behaviour is covered by tests where practical
- [ ] User-visible changes have a [changelog entry](#changelog-entries) under `[Unreleased]` (or the PR is labelled `skip-changelog`)
- [ ] Public functions and types have doc comments
- [ ] The PR description explains *what* changed and *why*
- [ ] Breaking changes are called out explicitly

---

## Code review

Every change reaches `main` through a pull request. The `main` branch ruleset enforces this for everyone, maintainers included, with no bypass.

**How review works.** The required checks run automatically: builds and tests on all three OSes, the race detector, CodeQL, Semgrep, secret scanning and the changelog check. Automated reviewers (GitHub Copilot and CodeRabbit) comment on the diff. Then a maintainer reviews it. GitHub requests the review from the maintainers listed in [`CODEOWNERS`](.github/CODEOWNERS). While the project has a single maintainer, the maintainer's own pull requests are merged after the checks pass and the automated review comments are addressed. See [`GOVERNANCE.md`](GOVERNANCE.md).

**What the reviewer checks:**

1. **Correctness.** The change does what the PR says, and edge cases and error paths are handled.
2. **All three platforms.** Platform-specific files have their counterparts, and nothing assumes one OS.
3. **Security.** No new `PATH` lookups, unquoted shell input, secrets, plaintext HTTP or weakened update verification. If the change affects a claim in the [assurance case](docs/assurance-case.md), the document is updated too.
4. **Tests.** New behaviour and bug fixes come with tests, and parsers of untrusted input with fuzz targets.
5. **Style.** The [coding standards](#coding-standards) are followed.
6. **Docs and changelog.** User-visible changes have a changelog entry, and the docs still describe what the code does.

**What's required to merge:** every required check passes, the branch is up to date with `main`, review comments are resolved, and a maintainer approves (or, for the maintainer's own PRs, merges it).

---

## Reporting bugs

Use the [Bug Report template](https://github.com/BrainStation-23/SentinelGo/issues/new?template=bug_report.yml).

A good bug report includes:

- The SentinelGo version (`sentinelgo -version`)
- OS and architecture (e.g. Ubuntu 22.04 amd64, Windows 11 x64)
- Steps to reproduce — the shorter the better
- What you expected vs. what actually happened
- Relevant log output (redact any credentials or PII)

---

## Suggesting features

Use the [Feature Request template](https://github.com/BrainStation-23/SentinelGo/issues/new?template=feature_request.yml).

Before opening, search existing issues to see if it has been discussed. Include:

- The problem you are trying to solve
- Your proposed solution or approach
- Any alternatives you have considered
- Whether you are willing to implement it

---

## Cross-platform rules

SentinelGo runs on Linux, macOS, and Windows. Every change must respect this:

- **No CGO.** All builds use `CGO_ENABLED=0`. Never introduce `import "C"`.
- **Build tags.** Platform-specific code lives in `_linux.go`, `_darwin.go`, `_windows.go` files or behind `//go:build` tags. Add a matching stub (`_stub.go`) for platforms that do not apply.
- **Test on all three.** CI runs tests on `ubuntu-latest`, `macos-latest`, and `windows-latest`. If you only have one OS locally, `make verify-cross` catches most type errors.
- **Paths.** Use `filepath.Join` and `os.UserHomeDir()` — never hardcode `/` or `\` separators.

---

## Questions

For general questions that are not bugs or feature requests, open a [Discussion](https://github.com/BrainStation-23/SentinelGo/discussions) rather than an issue.
