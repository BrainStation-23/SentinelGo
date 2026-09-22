//go:build !windows

package paths

// Unix keeps the layout it already had. The Windows relocation was driven by the
// C:\ root's inherited "Authenticated Users:(OI)(CI)(IO)(M)" ACE, which has no
// Unix equivalent: /opt is root-owned and mode 0755 by convention, so a
// non-root user cannot replace the binary there.
//
// The exposure that did exist here was the installer's own doing -- it ran
// "chmod -R 755" across the tree after dropping config.json in, publishing the
// agent's credentials to every local user, and chowned the root-executed binary
// to an unprivileged account. Both are fixed in installation-doc/install.sh;
// neither needed a new location.
const (
	unixInstallDir = "/opt/sentinelgo"
	unixDataDir    = "/opt/sentinelgo/.sentinelgo"
)

func installDir() string { return unixInstallDir }

func dataDir() string { return unixDataDir }

// legacyInstallDir returns "" because Unix was never relocated, which is what
// tells the migration logic there is nothing to do.
func legacyInstallDir() string { return "" }
