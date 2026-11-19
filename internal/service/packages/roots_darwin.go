package packages

// systemRoots are machine-wide installs: Homebrew (Apple silicon and Intel),
// the python.org framework installer, the system Ruby and CRAN's R.
func systemRoots() []root {
	return append(unixSystemRoots(),
		root{kindNodeModules, "/opt/homebrew/lib/node_modules"},
		root{kindNodeModules, "/usr/local/lib/node_modules"},
		root{kindSitePackages, "/opt/homebrew/lib/python3*/site-packages"},
		root{kindSitePackages, "/usr/local/lib/python3*/site-packages"},
		root{kindSitePackages, "/Library/Frameworks/Python.framework/Versions/*/lib/python*/site-packages"},
		root{kindGemDir, "/opt/homebrew/lib/ruby/gems/*"},
		root{kindGemDir, "/Library/Ruby/Gems/*"},
		root{kindRLibrary, "/Library/Frameworks/R.framework/Versions/*/Resources/library"},
		root{kindRLibrary, "/opt/homebrew/lib/R/*/site-library"},
		root{kindRLibrary, "/usr/local/lib/R/*/site-library"},
	)
}

// homeRoots are per-user installs under a home directory.
func homeRoots() []homeRoot {
	return append(unixHomeRoots(),
		homeRoot{kindNodeModules, "Library/Application Support/fnm/node-versions/*/installation/lib/node_modules"},
		homeRoot{kindPnpmGlobal, "Library/pnpm/global/*/node_modules"},
		// pip install --user with the system or python.org Python.
		homeRoot{kindSitePackages, "Library/Python/*/lib/python/site-packages"},
		// pipx 1.3+ on macOS.
		homeRoot{kindSitePackages, "Library/Application Support/pipx/venvs/*/lib/python*/site-packages"},
		// R's per-user library (R 4.x: Library/R/<arch>/<version>/library).
		homeRoot{kindRLibrary, "Library/R/*/library"},
		homeRoot{kindRLibrary, "Library/R/*/*/library"},
	)
}
