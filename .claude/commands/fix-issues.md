Work through open GitHub issues one at a time: fix each on its own branch off `dev`, open a PR back into `dev` with auto-merge, and wait for it to merge before starting the next. Arguments: $ARGUMENTS

If arguments are given, they are the issue numbers to work on, in that order (e.g. `135 136 137`). Otherwise work on every open issue.

## 1. Pick the queue

```bash
gh issue list --state open --limit 1000 --json number,title,labels,body   # gh pages through results up to --limit
```

- Skip tracking/epic issues whose body is mainly a checklist of other issues (e.g. "[Installers] ..." parents). They close when their children do.
- Skip issues labelled `question`, `wontfix`, `duplicate`, or that need a decision only the user can make. List them in the final report.
- Order the rest by dependency: if an issue says it depends on / builds on another (e.g. "AG-3 needs AG-2"), the dependency goes first. Otherwise oldest first, bugs before enhancements.
- Before starting an issue, check for earlier attempts: `git log --oneline --all --grep "#<n>"` and `gh pr list --state all --search "<n> in:body"`. If a previous PR was reverted, read the revert commit/PR to learn why and don't repeat that mistake.

Print the queue (number, title, why it's in that order) before starting.

## 2. For each issue

1. **Sync and branch off `dev`:**
   ```bash
   git checkout dev && git pull --ff-only origin dev
   git checkout -b fix/<n>-<short-slug>     # feat/<n>-<slug> for enhancements
   ```
2. **Understand it:** `gh issue view <n> --comments`. Read the code it touches. Follow `CLAUDE.md` rules (no cgo, all Supabase access via `internal/supabase`, tokens only via the `cfg` accessors, wrap Supabase calls in `DoWithAuthRetry`, platform files validated for all three OSes).
3. **Fix it** with tests that fail before the fix and pass after. Keep the change scoped to the issue.
4. **Changelog:** add an entry under `## [Unreleased]` in `CHANGELOG.md` (right subsection: Added / Changed / Fixed / Security), referencing the issue. The `Changelog` check is required.
5. **Verify locally before pushing** (everything except gosec is a required CI check):
   ```bash
   # CI runs `gofmt -s -l .`. On a Windows checkout every file has CRLF and
   # shows up, so check the changed files with CR stripped:
   for f in $(git diff --name-only dev -- '*.go') $(git ls-files -o --exclude-standard -- '*.go'); do
     tr -d '\r' < "$f" | gofmt -s -l | sed "s|<standard input>|$f|"; done
   for os in linux darwin windows; do CGO_ENABLED=0 GOOS=$os go vet ./...; done
   go test ./...
   make check-no-cgo
   make verify-cross
   # golangci-lint v2.12.2 is not on PATH; install to temp and lint each OS:
   LINT_DIR=$(mktemp -d)
   GOBIN=$LINT_DIR go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
   for os in linux darwin windows; do CGO_ENABLED=0 GOOS=$os "$LINT_DIR/golangci-lint" run ./...; done
   # gosec is advisory in CI (continue-on-error), but its findings show up as
   # code-scanning alerts on the PR, so fix or annotate them too (e.g. G302 on 0700 dirs):
   for os in linux windows; do GOOS=$os gosec -quiet -exclude-dir=scripts ./...; done
   ```
   SonarCloud flags SQL built by string concatenation (S2077) even from constants; write queries as literals.
   `TestConfigLoadDefaultPath` in `internal/config` fails locally because the installed agent owns `C:\SentinelGo`; that one is environmental. Any other failure must be fixed.
6. **Commit and push:** descriptive message ending with `Fixes #<n>`. Then `git push -u origin <branch>`.
7. **Open the PR into `dev` and enable auto-merge** (the `dev` ruleset only allows merge commits):
   ```bash
   gh pr create --base dev --head <branch> --title "<title>" --body "<summary, test plan, Fixes #<n>>"
   gh pr merge <pr> --auto --merge
   ```
   `Fixes #<n>` only auto-closes on merge into the default branch (`main`), so it will stay open after merging into `dev`; that's expected.
8. **Wait for the checks** (run in the background so you're notified, don't poll in a sleep loop):
   ```bash
   gh pr checks <pr> --watch --required --fail-fast
   ```
   - If a check fails: `gh run view <run-id> --log-failed`, fix on the same branch, push, and wait again. Don't disable checks, skip hooks, or add `skip-changelog` to get past a failure.
   - The ruleset requires the branch to be up to date with `dev`. If the PR is behind, run `gh pr update-branch <pr>` and wait again.
   - If a check fails for a reason unrelated to the change (flaky runner, external service outage), re-run it once with `gh run rerun <run-id> --failed`. If it fails again, stop and report it.
9. **Confirm the merge:** `gh pr view <pr> --json state,mergedAt` must show `MERGED`. Then comment on the issue: `gh issue comment <n> --body "Fixed in #<pr> (merged into dev)."`
10. Move to the next issue, starting again from step 1 (fresh branch off the updated `dev`).

## 3. Stop and ask when

- An issue is ambiguous, or the fix needs a backend/Supabase schema change, a new dependency, or a breaking config change.
- The same check fails three times after attempted fixes.
- Anything would require pushing to `dev` or `main` directly, force-pushing a shared branch, or bypassing a ruleset.

## 4. Final report

A table of each issue: PR link, merged / skipped / blocked, and one line on what changed or why it was skipped.
