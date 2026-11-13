# Changelog fragments

Every pull request with a user-visible change adds **one file here** instead of
editing `CHANGELOG.md`. Pull requests then never conflict over the changelog, so
they merge in any order without a rebase and a CI re-run. Releasing folds the
files into `CHANGELOG.md` under the new version and deletes them (see
[RELEASE.md](../RELEASE.md)).

## Name

`<issue>-<a-few-words>.<type>.md`, all lower case, for example
`484-audit-severity.changed.md`. `<type>` picks the group in the release notes:

| Type | Group |
|---|---|
| `added` | Added |
| `changed` | Changed |
| `deprecated` | Deprecated |
| `removed` | Removed |
| `fixed` | Fixed |
| `security` | Security (include the CVE or GHSA ID once published) |

A change that belongs in two groups gets two files.

## Content

One or more entries, each a `- ` line; indent any line that continues an entry.
No headings. Write for someone running the agent, not for reviewers:

```markdown
- Updater: a binary that fails its checksum is deleted instead of left on disk (#123).
```

## Checks

The required **Changelog** check fails when a pull request adds no fragment
(unless it is labelled `skip-changelog`), when a fragment is misnamed or
malformed, or when `[Unreleased]` in `CHANGELOG.md` has entries. Run
`make changelog-check` locally.
