# Contributing to SentinelGo

Thank you for taking the time to contribute! Every bug report, feature idea, documentation fix, and code improvement makes SentinelGo better for everyone.

---

## Table of contents

- [Code of Conduct](#code-of-conduct)
- [Ways to contribute](#ways-to-contribute)
- [Getting started](#getting-started)
- [Development workflow](#development-workflow)
- [Commit style](#commit-style)
- [Pull request checklist](#pull-request-checklist)
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

## Pull request checklist

Before marking your PR ready for review, confirm:

- [ ] `make test` passes on your machine
- [ ] `make verify-cross` passes (no type errors on any OS)
- [ ] `make check-no-cgo` passes (no `import "C"` introduced)
- [ ] `gofmt -s -l .` prints nothing (all files formatted)
- [ ] New behaviour is covered by tests where practical
- [ ] Public functions and types have doc comments
- [ ] The PR description explains *what* changed and *why*
- [ ] Breaking changes are called out explicitly

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
