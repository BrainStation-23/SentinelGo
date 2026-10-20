//go:build linux

package software

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// withTempDir points *dir at a fresh temp dir for the duration of the test.
func withTempDir(t *testing.T, dir *string) string {
	t.Helper()
	orig := *dir
	*dir = t.TempDir()
	t.Cleanup(func() { *dir = orig })
	return *dir
}

// touch creates path with size bytes and the given mtime.
func touch(t *testing.T, path string, size int, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatal(err)
	}
}

func TestParseDebPackagesMetadata(t *testing.T) {
	info := withTempDir(t, &dpkgInfoDir)
	curlTime := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	libcTime := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	touch(t, filepath.Join(info, "curl.list"), 0, curlTime)
	touch(t, filepath.Join(info, "libc6:amd64.list"), 0, libcTime)

	input := "ii \tcurl\t7.88.1\t512\tamd64\tUbuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>\n" +
		"ii \tlibc6\t2.39\t12000\tamd64\tGNU Libc Maintainers <debian-glibc@lists.debian.org>\n" +
		"ii \ttzdata\t2024a\t\tall\t\n"
	var got []SoftwareInfo
	parseDebPackages([]byte(input), &got)
	assertKnownSource(t, got)
	if len(got) != 3 {
		t.Fatalf("got %d packages, want 3", len(got))
	}

	curl := got[0]
	if curl.Publisher != "Ubuntu Developers" || curl.SizeBytes != 512*1024 || curl.Architecture != "x64" ||
		curl.InstallDate != "2026-03-04T05:06:07Z" {
		t.Errorf("curl metadata = %+v", curl)
	}
	if libc := got[1]; libc.InstallDate != "2025-01-02T03:04:05Z" {
		t.Errorf("libc6 (multi-arch list name) InstallDate = %q", libc.InstallDate)
	}
	tz := got[2]
	if tz.Publisher != "" || tz.SizeBytes != 0 || tz.Architecture != "noarch" || tz.InstallDate != "" {
		t.Errorf("tzdata should only report its architecture, got %+v", tz)
	}
}

func TestParseRPMPackagesMetadata(t *testing.T) {
	input := "bash\t5.2.26\t8210000\t1700000000\tx86_64\tRed Hat, Inc.\n" +
		"gpg-pubkey\tfd431d51\t0\t1690000000\t(none)\t(none)\n"
	var got []SoftwareInfo
	parseRPMPackages([]byte(input), &got)
	assertKnownSource(t, got)
	if len(got) != 2 {
		t.Fatalf("got %d packages, want 2", len(got))
	}
	bash := got[0]
	if bash.Publisher != "Red Hat, Inc." || bash.SizeBytes != 8210000 || bash.Architecture != "x64" ||
		bash.InstallDate != "2023-11-14T22:13:20Z" || bash.FirstSeenAt != bash.InstallDate {
		t.Errorf("bash metadata = %+v", bash)
	}
	key := got[1]
	if key.Publisher != "" || key.Architecture != "" || key.SizeBytes != 0 {
		t.Errorf("(none) placeholders must be left out, got %+v", key)
	}
}

// Multilib packages share a name across architectures; each must keep its own
// catalog entry. Repeated names with one architecture (gpg-pubkey) are left as
// they are.
func TestParseRPMPackagesMultilib(t *testing.T) {
	input := "glibc\t2.39\t100\t1700000000\tx86_64\tFedora Project\n" +
		"glibc\t2.39\t90\t1700000000\ti686\tFedora Project\n" +
		"gpg-pubkey\taaaa\t0\t1690000000\t(none)\t(none)\n" +
		"gpg-pubkey\tbbbb\t0\t1690000000\t(none)\t(none)\n"
	var got []SoftwareInfo
	parseRPMPackages([]byte(input), &got)
	want := []string{"glibc:x86_64", "glibc:i686", "gpg-pubkey", "gpg-pubkey"}
	if len(got) != len(want) {
		t.Fatalf("got %d packages, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Name != w {
			t.Errorf("[%d] Name = %q, want %q", i, got[i].Name, w)
		}
	}
	if got[0].SoftwarePackage != "glibc" {
		t.Errorf("SoftwarePackage = %q, want the unqualified name", got[0].SoftwarePackage)
	}
}

func TestParseSnapPackagesMetadata(t *testing.T) {
	blobs := withTempDir(t, &snapBlobDir)
	mtime := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	touch(t, filepath.Join(blobs, "firefox_4793.snap"), 2048, mtime)

	input := "Name     Version  Rev   Tracking       Publisher    Notes\n" +
		"firefox  131.0    4793  latest/stable  mozilla**    -\n" +
		"hello    2.10     42    latest/stable  -            -\n"
	var got []SoftwareInfo
	parseSnapPackages([]byte(input), &got)
	assertKnownSource(t, got)
	if len(got) != 2 {
		t.Fatalf("got %d packages, want 2", len(got))
	}
	ff := got[0]
	if ff.Publisher != "mozilla" || ff.InstallDate != "2026-05-06T07:08:09Z" || ff.SizeBytes != 2048 {
		t.Errorf("firefox metadata = %+v", ff)
	}
	hello := got[1]
	if hello.Publisher != "" || hello.InstallDate != "" || hello.SizeBytes != 0 {
		t.Errorf("hello should have no metadata, got %+v", hello)
	}
}

func TestSnapPublisher(t *testing.T) {
	cases := map[string]string{
		"canonical**": "canonical",
		"mozilla*":    "mozilla",
		"canonical✓":  "canonical",
		"kde✪":        "kde",
		"someone":     "someone",
		"-":           "",
	}
	for in, want := range cases {
		if got := snapPublisher(in); got != want {
			t.Errorf("snapPublisher(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseFlatpakPackagesMetadata(t *testing.T) {
	input := "org.gimp.GIMP\tGNU Image Manipulation Program\t2.10.38\tflathub\tx86_64\n" +
		"org.example.NoName\t\t1.0\tfedora\taarch64\n"
	var got []SoftwareInfo
	parseFlatpakPackages([]byte(input), &got)
	assertKnownSource(t, got)
	if len(got) != 2 {
		t.Fatalf("got %d packages, want 2", len(got))
	}
	gimp := got[0]
	if gimp.Name != "GNU Image Manipulation Program" || gimp.InstalledVersion != "2.10.38" ||
		gimp.Publisher != "flathub" || gimp.Architecture != "x64" || gimp.SoftwarePackage != "org.gimp.GIMP" {
		t.Errorf("GIMP = %+v", gimp)
	}
	if noName := got[1]; noName.Name != "org.example.NoName" || noName.Architecture != "arm64" {
		t.Errorf("unnamed app should fall back to its ID, got %+v", noName)
	}
}
