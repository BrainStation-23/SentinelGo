//go:build !windows

package packages

import "path"

// condaDirs are the folder names of the conda installers (Anaconda,
// Miniconda, Miniforge, Mambaforge), in a home or a system folder.
var condaDirs = []string{"anaconda3", "miniconda3", "miniforge3", "mambaforge"}

// condaSitePackages are the base env and the named envs of a conda install
// at dir. Only pip-visible metadata (dist-info, egg-info) is read:
// conda-only packages (conda-meta/*.json) aren't PyPI packages.
func condaSitePackages(dir string) []string {
	return []string{
		path.Join(dir, "lib/python*/site-packages"),
		path.Join(dir, "envs/*/lib/python*/site-packages"),
	}
}

// unixHomeRoots are the per-user locations macOS and Linux share.
func unixHomeRoots() []homeRoot {
	roots := []homeRoot{
		// npm with a user prefix, nvm, Volta, Bun, asdf and mise.
		{kindNodeModules, ".npm-global/lib/node_modules"},
		{kindNodeModules, ".nvm/versions/node/*/lib/node_modules"},
		{kindNodeModules, ".volta/tools/image/packages/*/lib/node_modules"},
		{kindNodeModules, ".bun/install/global/node_modules"},
		{kindNodeModules, ".asdf/installs/nodejs/*/lib/node_modules"},
		{kindNodeModules, ".local/share/mise/installs/node/*/lib/node_modules"},
		// pip install --user, pyenv, asdf, mise.
		{kindSitePackages, ".local/lib/python*/site-packages"},
		{kindSitePackages, ".pyenv/versions/*/lib/python*/site-packages"},
		{kindSitePackages, ".asdf/installs/python/*/lib/python*/site-packages"},
		{kindSitePackages, ".local/share/mise/installs/python/*/lib/python*/site-packages"},
		// pipx (1.3+ and older), uv tools and uv-managed Pythons.
		{kindSitePackages, ".local/share/pipx/venvs/*/lib/python*/site-packages"},
		{kindSitePackages, ".local/pipx/venvs/*/lib/python*/site-packages"},
		{kindSitePackages, ".local/share/uv/tools/*/lib/python*/site-packages"},
		{kindSitePackages, ".local/share/uv/python/*/lib/python*/site-packages"},
		// conda envs created outside the install (conda create when the base
		// isn't writable).
		{kindSitePackages, ".conda/envs/*/lib/python*/site-packages"},
		// composer global require (COMPOSER_HOME is one of these).
		{kindComposerHome, ".composer"},
		{kindComposerHome, ".config/composer"},
		// .NET global tools and the NuGet package cache.
		{kindNuGetTools, ".dotnet/tools/.store"},
		{kindNuGetCache, ".nuget/packages"},
		// Maven and Gradle caches.
		{kindMavenRepo, ".m2/repository"},
		{kindM2Settings, ".m2/settings.xml"},
		{kindGradleCache, ".gradle/caches/modules-2/files-2.1"},
		// go install binaries and the module cache (GOPATH=~/go).
		{kindGoBin, "go/bin"},
		{kindGoModCache, "go/pkg/mod/cache/download"},
		// cargo install and the crates.io download cache.
		{kindCargoHome, ".cargo"},
		{kindCargoCache, ".cargo/registry/cache/*"},
		// gem install --user-install, rbenv, rvm, asdf, mise.
		{kindGemDir, ".gem/ruby/*"},
		{kindGemDir, ".local/share/gem/ruby/*"},
		{kindGemDir, ".rbenv/versions/*/lib/ruby/gems/*"},
		{kindGemDir, ".rvm/gems/*"},
		{kindGemDir, ".asdf/installs/ruby/*/lib/ruby/gems/*"},
		{kindGemDir, ".local/share/mise/installs/ruby/*/lib/ruby/gems/*"},
		// dart pub global activate and the Pub cache.
		{kindPubGlobal, ".pub-cache/global_packages/*"},
		{kindPubCache, ".pub-cache/hosted/pub.dev"},
		{kindPubCache, ".pub-cache/hosted/pub.dartlang.org"},
	}
	for _, d := range condaDirs {
		for _, p := range condaSitePackages(d) {
			roots = append(roots, homeRoot{kindSitePackages, p})
		}
	}
	return roots
}

// unixSystemRoots are the machine-wide locations macOS and Linux share.
func unixSystemRoots() []root {
	var roots []root
	for _, d := range []string{"/opt/conda", "/opt/anaconda3", "/opt/miniconda3", "/opt/miniforge3"} {
		for _, p := range condaSitePackages(d) {
			roots = append(roots, root{kindSitePackages, p})
		}
	}
	return append(roots,
		root{kindGemDir, "/usr/local/lib/ruby/gems/*"},
	)
}
