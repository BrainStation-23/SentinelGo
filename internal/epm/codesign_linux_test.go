//go:build linux

package epm

import "testing"

func TestParseDpkgOwner_SingleMatch(t *testing.T) {
	got, err := parseDpkgOwner("coreutils: /usr/bin/whoami\n")
	if err != nil {
		t.Fatalf("parseDpkgOwner: %v", err)
	}
	if got != "coreutils" {
		t.Errorf("parseDpkgOwner = %q, want %q", got, "coreutils")
	}
}

func TestParseDpkgOwner_MultiplePackagesTakesFirst(t *testing.T) {
	got, err := parseDpkgOwner("pkg-a: /usr/bin/shared\npkg-b: /usr/bin/shared\n")
	if err != nil {
		t.Fatalf("parseDpkgOwner: %v", err)
	}
	if got != "pkg-a" {
		t.Errorf("parseDpkgOwner = %q, want %q", got, "pkg-a")
	}
}

func TestParseDpkgOwner_NoColonIsError(t *testing.T) {
	// Note: dpkg -S's actual "not found" message ("dpkg-query: no path found
	// matching pattern ...") does contain a colon (after "dpkg-query") and
	// would misparse as package name "dpkg-query" if fed to this function —
	// but in production that message is dpkg's stderr on a non-zero exit,
	// which dpkgOwner's exec.Command.Output() call already turns into an
	// error before parseDpkgOwner ever sees it. This test exercises a
	// genuinely colon-free string to validate the defensive branch itself.
	_, err := parseDpkgOwner("no such package found\n")
	if err == nil {
		t.Fatal("expected error when output has no 'package: path' colon")
	}
}

func TestParseDpkgOwner_EmptyPackageNameIsError(t *testing.T) {
	_, err := parseDpkgOwner(": /usr/bin/whoami\n")
	if err == nil {
		t.Fatal("expected error for empty package name")
	}
}
