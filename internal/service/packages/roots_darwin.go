package packages

// systemRoots are machine-wide installs: Homebrew (Apple silicon and Intel)
// and the python.org framework installer.
func systemRoots() []root {
	return []root{
		{kindNodeModules, "/opt/homebrew/lib/node_modules"},
		{kindNodeModules, "/usr/local/lib/node_modules"},
		{kindSitePackages, "/opt/homebrew/lib/python3*/site-packages"},
		{kindSitePackages, "/usr/local/lib/python3*/site-packages"},
		{kindSitePackages, "/Library/Frameworks/Python.framework/Versions/*/lib/python*/site-packages"},
	}
}

// homeRoots are per-user installs under a home directory.
func homeRoots() []homeRoot {
	return append(unixHomeRoots(),
		homeRoot{kindNodeModules, "Library/Application Support/fnm/node-versions/*/installation/lib/node_modules"},
		// pip install --user with the system or python.org Python.
		homeRoot{kindSitePackages, "Library/Python/*/lib/python/site-packages"},
	)
}
