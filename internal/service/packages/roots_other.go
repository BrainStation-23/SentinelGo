//go:build !windows && !darwin

package packages

// systemRoots are machine-wide installs: distribution packages and
// /usr/local (npm install -g as root, pip install as root, source builds).
func systemRoots() []root {
	return append(unixSystemRoots(),
		root{kindNodeModules, "/usr/lib/node_modules"},
		root{kindNodeModules, "/usr/local/lib/node_modules"},
		root{kindSitePackages, "/usr/lib/python3*/site-packages"},
		root{kindSitePackages, "/usr/lib/python3/dist-packages"},
		root{kindSitePackages, "/usr/lib64/python3*/site-packages"},
		root{kindSitePackages, "/usr/local/lib/python3*/site-packages"},
		root{kindSitePackages, "/usr/local/lib/python3*/dist-packages"},
		root{kindGemDir, "/usr/lib/ruby/gems/*"},
		root{kindGemDir, "/var/lib/gems/*"},
		root{kindRLibrary, "/usr/lib/R/library"},
		root{kindRLibrary, "/usr/lib/R/site-library"},
		root{kindRLibrary, "/usr/lib64/R/library"},
		root{kindRLibrary, "/usr/local/lib/R/site-library"},
	)
}

// homeRoots are per-user installs under a home directory.
func homeRoots() []homeRoot {
	return append(unixHomeRoots(),
		homeRoot{kindNodeModules, ".local/share/fnm/node-versions/*/installation/lib/node_modules"},
		homeRoot{kindPnpmGlobal, ".local/share/pnpm/global/*/node_modules"},
		// R's per-user library: ~/R/<platform>-library/<version>.
		homeRoot{kindRLibrary, "R/*-library/*"},
	)
}
