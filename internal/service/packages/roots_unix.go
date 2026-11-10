//go:build !windows

package packages

// unixHomeRoots are the per-user locations macOS and Linux share.
func unixHomeRoots() []homeRoot {
	return []homeRoot{
		// npm with a user prefix, nvm, Volta.
		{kindNodeModules, ".npm-global/lib/node_modules"},
		{kindNodeModules, ".nvm/versions/node/*/lib/node_modules"},
		{kindNodeModules, ".volta/tools/image/packages/*/lib/node_modules"},
		// pip install --user, pyenv.
		{kindSitePackages, ".local/lib/python*/site-packages"},
		{kindSitePackages, ".pyenv/versions/*/lib/python*/site-packages"},
		// composer global require (COMPOSER_HOME is one of these).
		{kindComposerHome, ".composer"},
		{kindComposerHome, ".config/composer"},
	}
}
