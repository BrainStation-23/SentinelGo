// Command checkversion is the release build's version gate.
//
// It runs as `go run ./scripts/checkversion` from the Makefile, deliberately in
// Go rather than as a shell script: the Makefile is kept shell-agnostic so it
// works when GNU Make drives recipes through cmd.exe on Windows, and a .sh gate
// would simply not run there — which is exactly the environment where an
// accidental `-dirty` release is easiest to produce.
//
// It answers three questions, all of which were answered wrongly by the build
// that prompted this gate (a binary stamped "v3.2.6-4-g40f52e7-dirty" while
// v3.2.8 was the deployed version):
//
//  1. Is the version string an explicit, clean release version?
//  2. Is the working tree clean, so the artifact is reproducible?
//  3. Does the tag actually point at HEAD, so the version names what is built?
//
// The third is what catches an unreachable tag. `git describe` walks back to the
// newest tag REACHABLE from HEAD, so building on a branch that does not contain
// v3.2.7 or v3.2.8 silently yields a v3.2.6 base — an older version than
// production is already running.
//
// It never creates, moves or pushes a tag. Publishing is a human decision; this
// only refuses to build something that would misrepresent itself.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"sentinelgo/internal/version"
)

func main() {
	var (
		raw         = flag.String("version", "", "version string to validate (usually $(VERSION))")
		requireGit  = flag.Bool("require-clean-tree", false, "fail when the working tree has uncommitted changes")
		requireHead = flag.Bool("require-tag-at-head", false, "fail unless the version's tag points at HEAD")
	)
	flag.Parse()

	if err := run(*raw, *requireGit, *requireHead); err != nil {
		fmt.Fprintf(os.Stderr, "\n❌ release version check failed\n\n    %v\n\n", err)
		fmt.Fprint(os.Stderr, guidance(*raw))
		os.Exit(1)
	}

	fmt.Printf("✅ release version %s accepted\n", *raw)
}

func run(raw string, requireCleanTree, requireTagAtHead bool) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("no version given; a release build requires an explicit VERSION (e.g. make release VERSION=v3.2.9)")
	}

	if err := version.Validate(raw); err != nil {
		return err
	}

	if requireCleanTree {
		if err := checkCleanTree(); err != nil {
			return err
		}
	}

	if requireTagAtHead {
		if err := checkTagAtHead(raw); err != nil {
			return err
		}
	}

	return nil
}

// checkCleanTree fails when `git status --porcelain` reports anything.
//
// A release built from a modified tree cannot be rebuilt from its tag, so the
// version number on the artifact is a claim nobody can verify later.
func checkCleanTree() error {
	out, err := gitOutput("status", "--porcelain")
	if err != nil {
		// Not a git checkout (a source tarball, a container build context).
		// Nothing to verify, and refusing here would block legitimate builds.
		fmt.Fprintln(os.Stderr, "note: skipping clean-tree check (not a git working tree)")
		return nil
	}
	if strings.TrimSpace(out) == "" {
		return nil
	}

	changed := strings.Count(strings.TrimSpace(out), "\n") + 1
	return fmt.Errorf("working tree has %d uncommitted change(s); commit or stash them before building a release", changed)
}

// checkTagAtHead fails unless the tag named by the version resolves to the
// commit being built.
func checkTagAtHead(raw string) error {
	tag := strings.TrimSpace(raw)

	head, err := gitOutput("rev-parse", "HEAD")
	if err != nil {
		fmt.Fprintln(os.Stderr, "note: skipping tag-at-HEAD check (not a git working tree)")
		return nil
	}

	tagged, err := gitOutput("rev-parse", tag+"^{commit}")
	if err != nil {
		return fmt.Errorf("tag %s does not exist in this repository; create it on the commit you intend to release", tag)
	}

	if strings.TrimSpace(head) != strings.TrimSpace(tagged) {
		return fmt.Errorf(
			"tag %s points at %s but HEAD is %s; the artifact would carry a version naming a different commit",
			tag, short(tagged), short(head))
	}
	return nil
}

func gitOutput(args ...string) (string, error) {
	cmd := exec.Command("git", args...) // #nosec G204 - fixed argument list
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func short(hash string) string {
	h := strings.TrimSpace(hash)
	if len(h) > 8 {
		return h[:8]
	}
	return h
}

// guidance prints the recovery steps, so the failure is self-explaining rather
// than sending someone to read the Makefile.
func guidance(raw string) string {
	info := version.Parse(raw)

	var b strings.Builder
	b.WriteString("A release build needs a version that names exactly what is being built.\n\n")

	switch {
	case info.Dirty:
		b.WriteString("  This build has uncommitted changes. Commit or stash them, then rebuild.\n")
	case info.Commit != "":
		b.WriteString(fmt.Sprintf(
			"  %q is git-describe output: %d commit(s) past %s. That base tag is only\n"+
				"  the newest tag REACHABLE from HEAD, so it can name an older release than\n"+
				"  the one already deployed.\n", raw, info.CommitsAhead, info.Semver))
	case raw == version.DevelopmentFallback || raw == "":
		b.WriteString("  No version was injected. Pass one explicitly.\n")
	default:
		b.WriteString(fmt.Sprintf("  %q is not of the form vX.Y.Z.\n", raw))
	}

	b.WriteString("\n  Recommended procedure:\n")
	b.WriteString("    1. git tag -a vX.Y.Z -m \"vX.Y.Z\"     # on the commit you intend to release\n")
	b.WriteString("    2. git push origin vX.Y.Z\n")
	b.WriteString("    3. make release VERSION=vX.Y.Z\n\n")
	b.WriteString("  Development builds are unaffected: `make build` keeps using git-derived\n")
	b.WriteString("  metadata, and such a binary simply declines to self-update.\n\n")
	return b.String()
}
