package packages

import (
	"os"
	"path/filepath"
)

// condaDirs are the folder names of the conda installers (Anaconda,
// Miniconda, Miniforge, Mambaforge), in a profile or ProgramData.
var condaDirs = []string{"anaconda3", "miniconda3", "miniforge3", "mambaforge"}

// condaSitePackages are the base env and the named envs of a conda install
// at dir. Only pip-visible metadata (dist-info, egg-info) is read:
// conda-only packages (conda-meta\*.json) aren't PyPI packages.
func condaSitePackages(dir string) []string {
	return []string{
		filepath.Join(dir, "Lib", "site-packages"),
		filepath.Join(dir, "envs", "*", "Lib", "site-packages"),
	}
}

// systemRoots are machine-wide installs: Node.js and "install for all
// users" Python under Program Files, the classic C:\PythonXY layout,
// conda for all users, RubyInstaller and R.
func systemRoots() []root {
	programFiles := envOr("ProgramFiles", `C:\Program Files`)
	programData := envOr("ProgramData", `C:\ProgramData`)
	drive := envOr("SystemDrive", "C:") + `\`
	roots := []root{
		{kindNodeModules, filepath.Join(programFiles, "nodejs", "node_modules")},
		{kindSitePackages, filepath.Join(programFiles, "Python*", "Lib", "site-packages")},
		{kindSitePackages, filepath.Join(drive, "Python*", "Lib", "site-packages")},
		{kindGemDir, filepath.Join(drive, "Ruby*", "lib", "ruby", "gems", "*")},
		{kindRLibrary, filepath.Join(programFiles, "R", "R-*", "library")},
	}
	for _, d := range condaDirs {
		for _, p := range condaSitePackages(filepath.Join(programData, d)) {
			roots = append(roots, root{kindSitePackages, p})
		}
	}
	return roots
}

// homeRoots are per-user installs under a profile directory.
func homeRoots() []homeRoot {
	roots := []homeRoot{
		// npm install -g (default prefix %APPDATA%\npm), nvm-windows, fnm, Volta.
		{kindNodeModules, `AppData\Roaming\npm\node_modules`},
		{kindNodeModules, `AppData\Roaming\nvm\v*\node_modules`},
		{kindNodeModules, `AppData\Roaming\fnm\node-versions\*\installation\node_modules`},
		{kindNodeModules, `AppData\Local\Volta\tools\image\packages\*\node_modules`},
		// python.org per-user installs, pip install --user, pyenv-win.
		{kindSitePackages, `AppData\Local\Programs\Python\Python*\Lib\site-packages`},
		{kindSitePackages, `AppData\Roaming\Python\Python*\site-packages`},
		{kindSitePackages, `.pyenv\pyenv-win\versions\*\Lib\site-packages`},
		// Bun and pnpm global installs (pnpm's node_modules link into its store).
		{kindNodeModules, `.bun\install\global\node_modules`},
		{kindPnpmGlobal, `AppData\Local\pnpm\global\*\node_modules`},
		// pipx (older and 1.3+), uv tools and uv-managed Pythons (uv 0.4+
		// keeps them under %APPDATA%\uv\data, older ones under %APPDATA%\uv).
		{kindSitePackages, `pipx\venvs\*\Lib\site-packages`},
		{kindSitePackages, `AppData\Local\pipx\pipx\venvs\*\Lib\site-packages`},
		{kindSitePackages, `AppData\Roaming\uv\data\tools\*\Lib\site-packages`},
		{kindSitePackages, `AppData\Roaming\uv\data\python\*\Lib\site-packages`},
		{kindSitePackages, `AppData\Roaming\uv\tools\*\Lib\site-packages`},
		{kindSitePackages, `AppData\Roaming\uv\python\*\Lib\site-packages`},
		// conda envs created outside the install.
		{kindSitePackages, `.conda\envs\*\Lib\site-packages`},
		// Microsoft Store Python: pip install --user lands in its LocalCache.
		{kindSitePackages, `AppData\Local\Packages\PythonSoftwareFoundation.Python.3*\LocalCache\local-packages\Python3*\site-packages`},
		// composer global require (COMPOSER_HOME defaults to %APPDATA%\Composer).
		{kindComposerHome, `AppData\Roaming\Composer`},
		// .NET global tools and the NuGet package cache.
		{kindNuGetTools, `.dotnet\tools\.store`},
		{kindNuGetCache, `.nuget\packages`},
		// Maven and Gradle caches.
		{kindMavenRepo, `.m2\repository`},
		{kindM2Settings, `.m2\settings.xml`},
		{kindGradleCache, `.gradle\caches\modules-2\files-2.1`},
		// go install binaries and the module cache (GOPATH=%USERPROFILE%\go).
		{kindGoBin, `go\bin`},
		{kindGoModCache, `go\pkg\mod\cache\download`},
		// cargo install and the crates.io download cache.
		{kindCargoHome, `.cargo`},
		{kindCargoCache, `.cargo\registry\cache\*`},
		// gem install --user-install.
		{kindGemDir, `.gem\ruby\*`},
		// dart pub global activate and the Pub cache (%LOCALAPPDATA%\Pub\Cache).
		{kindPubGlobal, `AppData\Local\Pub\Cache\global_packages\*`},
		{kindPubCache, `AppData\Local\Pub\Cache\hosted\pub.dev`},
		// R's per-user library (R 4.2+: %LOCALAPPDATA%\R; older: Documents\R).
		{kindRLibrary, `AppData\Local\R\win-library\*`},
		{kindRLibrary, `Documents\R\win-library\*`},
	}
	for _, d := range condaDirs {
		for _, p := range condaSitePackages(d) {
			roots = append(roots, homeRoot{kindSitePackages, p})
		}
	}
	return roots
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
