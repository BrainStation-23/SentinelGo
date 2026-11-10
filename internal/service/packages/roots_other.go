//go:build !windows && !darwin

package packages

// systemRoots are machine-wide installs: distribution packages and
// /usr/local (npm install -g as root, pip install as root, source builds).
func systemRoots() []root {
	return []root{
		{kindNodeModules, "/usr/lib/node_modules"},
		{kindNodeModules, "/usr/local/lib/node_modules"},
		{kindSitePackages, "/usr/lib/python3*/site-packages"},
		{kindSitePackages, "/usr/lib/python3/dist-packages"},
		{kindSitePackages, "/usr/lib64/python3*/site-packages"},
		{kindSitePackages, "/usr/local/lib/python3*/site-packages"},
		{kindSitePackages, "/usr/local/lib/python3*/dist-packages"},
	}
}

// homeRoots are per-user installs under a home directory.
func homeRoots() []homeRoot {
	return append(unixHomeRoots(),
		homeRoot{kindNodeModules, ".local/share/fnm/node-versions/*/installation/lib/node_modules"},
	)
}
