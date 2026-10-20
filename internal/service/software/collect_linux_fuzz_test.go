//go:build linux

package software

// Fuzz targets for the Linux package-manager parsers. Package names, versions,
// maintainers and vendors are chosen by package authors, so the output of
// dpkg-query, rpm, snap and flatpak is untrusted input: parsing must never
// panic and every entry must have a name and a known source.
//
// The seed corpus runs as an ordinary unit test under `go test ./...`.
// To actually fuzz:
//
//	go test -run='^$' -fuzz='^FuzzParseLinuxPackages$' -fuzztime=1m ./internal/service/software/

import "testing"

var linuxPackageSeeds = []string{
	"",
	"ii \tcurl\t7.88.1\t512\tamd64\tUbuntu Developers <x@y>\n",
	"rc \tneedrestart\t3.6\t\tall\t\n",
	"ii \tlibc6\t2.39\t1\tamd64\t\nii \tlibc6\t2.39\t1\ti386\t\n",
	"bash\t5.2\t8210000\t1700000000\tx86_64\tRed Hat, Inc.\n",
	"gpg-pubkey\tfd431d51\t0\t1690000000\t(none)\t(none)\n",
	"bash 5.2.15 2048 1700000000\n",
	"Name  Version  Rev  Tracking  Publisher  Notes\nfirefox 131.0 4793 latest/stable mozilla** -\n",
	"org.gimp.GIMP\tGNU Image Manipulation Program\t2.10\tflathub\tx86_64\n",
	"\t\t\t\t\t\n",
	"ii \t../../etc/passwd\t1\t-1\t../x\t\n",
	"x\t\x00\t99999999999999999999999\t-5\n",
}

func FuzzParseLinuxPackages(f *testing.F) {
	for _, s := range linuxPackageSeeds {
		f.Add(s)
	}
	origInfo, origSnap := dpkgInfoDir, snapBlobDir
	dpkgInfoDir, snapBlobDir = f.TempDir(), f.TempDir()
	f.Cleanup(func() { dpkgInfoDir, snapBlobDir = origInfo, origSnap })
	f.Fuzz(func(t *testing.T, input string) {
		parsers := map[string]func([]byte, *[]SoftwareInfo){
			"deb":     parseDebPackages,
			"rpm":     parseRPMPackages,
			"snap":    parseSnapPackages,
			"flatpak": parseFlatpakPackages,
		}
		for name, parse := range parsers {
			var got []SoftwareInfo
			parse([]byte(input), &got)
			assertKnownSource(t, got)
			for _, sw := range got {
				if sw.Name == "" {
					t.Errorf("%s: entry without a name from %q", name, input)
				}
				if sw.SizeBytes < 0 {
					t.Errorf("%s: negative size %d from %q", name, sw.SizeBytes, input)
				}
			}
		}
	})
}
