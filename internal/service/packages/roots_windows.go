package packages

import (
	"os"
	"path/filepath"
)

// systemRoots are machine-wide installs: Node.js and "install for all
// users" Python under Program Files, and the classic C:\PythonXY layout.
func systemRoots() []root {
	programFiles := envOr("ProgramFiles", `C:\Program Files`)
	drive := envOr("SystemDrive", "C:") + `\`
	return []root{
		{kindNodeModules, filepath.Join(programFiles, "nodejs", "node_modules")},
		{kindSitePackages, filepath.Join(programFiles, "Python*", "Lib", "site-packages")},
		{kindSitePackages, filepath.Join(drive, "Python*", "Lib", "site-packages")},
	}
}

// homeRoots are per-user installs under a profile directory.
func homeRoots() []homeRoot {
	return []homeRoot{
		// npm install -g (default prefix %APPDATA%\npm), nvm-windows, fnm, Volta.
		{kindNodeModules, `AppData\Roaming\npm\node_modules`},
		{kindNodeModules, `AppData\Roaming\nvm\v*\node_modules`},
		{kindNodeModules, `AppData\Roaming\fnm\node-versions\*\installation\node_modules`},
		{kindNodeModules, `AppData\Local\Volta\tools\image\packages\*\node_modules`},
		// python.org per-user installs, pip install --user, pyenv-win.
		{kindSitePackages, `AppData\Local\Programs\Python\Python*\Lib\site-packages`},
		{kindSitePackages, `AppData\Roaming\Python\Python*\site-packages`},
		{kindSitePackages, `.pyenv\pyenv-win\versions\*\Lib\site-packages`},
		// composer global require (COMPOSER_HOME defaults to %APPDATA%\Composer).
		{kindComposerHome, `AppData\Roaming\Composer`},
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
