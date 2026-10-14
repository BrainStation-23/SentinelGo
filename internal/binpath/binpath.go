// Package binpath resolves well-known system binaries to a fixed absolute
// path before they are passed to os/exec, instead of a bare name that the
// OS resolves by searching $PATH.
//
// Searching PATH for an executable is a PATH-hijacking risk (CWE-426/427):
// if an attacker can write to any directory listed in PATH, or prepend a
// directory they control to it, a malicious binary with the matching name
// runs instead of the real one - a real concern for a service that runs
// with elevated privileges (root/SYSTEM). Resolve checks the binary's real,
// standard install locations (directories only an administrator can write
// to) and only falls back to the bare name - the previous, PATH-searching
// behavior - when none of those fixed locations exist, so an unusual
// install still works rather than breaking outright.
package binpath

import (
	"os"
	"path/filepath"
)

// windowsSystemRoot returns the Windows installation directory (normally
// C:\Windows, but not guaranteed - it's whatever %SystemRoot% says).
func windowsSystemRoot() string {
	if root := os.Getenv("SystemRoot"); root != "" {
		return root
	}
	return `C:\Windows`
}

// knownPaths maps a binary name to its candidate absolute paths, most
// common first. Built once at package init since the Windows entries depend
// on an environment variable.
var knownPaths = func() map[string][]string {
	sys32 := filepath.Join(windowsSystemRoot(), "System32")

	return map[string][]string{
		// macOS
		"launchctl":       {"/bin/launchctl"},
		"sh":              {"/bin/sh"},
		"xattr":           {"/usr/bin/xattr"},
		"codesign":        {"/usr/bin/codesign"},
		"spctl":           {"/usr/sbin/spctl"},
		"system_profiler": {"/usr/sbin/system_profiler"},
		"defaults":        {"/usr/bin/defaults"},
		"dscl":            {"/usr/bin/dscl"},
		"plutil":          {"/usr/bin/plutil"},
		"pmset":           {"/usr/bin/pmset"},
		"pwpolicy":        {"/usr/bin/pwpolicy"},
		"sysadminctl":     {"/usr/sbin/sysadminctl"},
		"systemsetup":     {"/usr/sbin/systemsetup"},
		"tmutil":          {"/usr/bin/tmutil"},

		// Linux
		"systemctl":  {"/usr/bin/systemctl", "/bin/systemctl"},
		"smartctl":   {"/usr/sbin/smartctl", "/sbin/smartctl"},
		"dpkg-query": {"/usr/bin/dpkg-query"},
		"rpm":        {"/usr/bin/rpm", "/bin/rpm"},
		"snap":       {"/usr/bin/snap"},
		"flatpak":    {"/usr/bin/flatpak"},
		"ufw":        {"/usr/sbin/ufw", "/sbin/ufw"},
		"sudo":       {"/usr/bin/sudo"},
		"env":        {"/usr/bin/env", "/bin/env"},

		// Linux compliance probes (osinfo/security, osinfo/users)
		"auditctl":         {"/usr/sbin/auditctl", "/sbin/auditctl"},
		"chronyc":          {"/usr/bin/chronyc", "/bin/chronyc"},
		"gsettings":        {"/usr/bin/gsettings", "/bin/gsettings"},
		"lastlog":          {"/usr/bin/lastlog", "/bin/lastlog"},
		"lastlog2":         {"/usr/bin/lastlog2", "/bin/lastlog2"},
		"loginctl":         {"/usr/bin/loginctl", "/bin/loginctl"},
		"needrestart":      {"/usr/sbin/needrestart", "/sbin/needrestart"},
		"needs-restarting": {"/usr/bin/needs-restarting", "/bin/needs-restarting"},
		"ntpq":             {"/usr/bin/ntpq", "/usr/sbin/ntpq"},
		"runuser":          {"/usr/sbin/runuser", "/sbin/runuser", "/usr/bin/runuser"},
		"timedatectl":      {"/usr/bin/timedatectl", "/bin/timedatectl"},

		// Linux + macOS (candidates cover both; order doesn't matter since
		// only one OS's paths will ever exist on a given host)
		"bash":    {"/bin/bash", "/usr/bin/bash"},
		"python3": {"/usr/bin/python3", "/usr/local/bin/python3", "/opt/homebrew/bin/python3"},
		"ps":      {"/bin/ps", "/usr/bin/ps"},
		"kill":    {"/bin/kill", "/usr/bin/kill"},
		"groups":  {"/usr/bin/groups", "/bin/groups"},
		"id":      {"/usr/bin/id", "/bin/id"},
		"stat":    {"/usr/bin/stat", "/bin/stat"},

		// Windows - System32 is writable only by admins/TrustedInstaller.
		"powershell": {filepath.Join(sys32, "WindowsPowerShell", "v1.0", "powershell.exe")},
		"taskkill":   {filepath.Join(sys32, "taskkill.exe")},
		"tasklist":   {filepath.Join(sys32, "tasklist.exe")},
		"netsh":      {filepath.Join(sys32, "netsh.exe")},
		"cmd":        {filepath.Join(sys32, "cmd.exe")},
		"auditpol":   {filepath.Join(sys32, "auditpol.exe")},
		"reg":        {filepath.Join(sys32, "reg.exe")},
		"sc.exe":     {filepath.Join(sys32, "sc.exe")},
		"secedit":    {filepath.Join(sys32, "secedit.exe")},

		// shutdown exists on all three OSes, at different paths.
		"shutdown": {"/sbin/shutdown", "/usr/sbin/shutdown", filepath.Join(sys32, "shutdown.exe")},
	}
}()

// Resolve returns the first of name's known candidate absolute paths that
// actually exists on this host, or name itself (unresolved) if none do -
// including when name has no known candidates at all. The fallback
// preserves the previous PATH-search behavior for that case rather than
// breaking functionality on a non-standard install.
func Resolve(name string) string {
	for _, candidate := range knownPaths[name] {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return name
}

// Lookup is the strict form of Resolve: for a known tool it returns the
// first candidate path that exists, and ok=false when none does, so the
// caller skips the tool instead of searching PATH for it. A name with no
// known candidates is returned unchanged with ok=true.
func Lookup(name string) (path string, ok bool) {
	candidates, known := knownPaths[name]
	if !known {
		return name, true
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, true
		}
	}
	return "", false
}
