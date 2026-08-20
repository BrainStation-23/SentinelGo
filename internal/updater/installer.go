package updater

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"sentinelgo/internal/winsec"
)

// atomicReplace replaces the running binary with newPath using an atomic rename.
// Not used on Windows (handled via restart batch script).
func atomicReplace(newPath string) error {
	selfPath, err := os.Executable()
	if err != nil {
		return err
	}

	dir := filepath.Dir(selfPath)
	tempPath := filepath.Join(dir, ".sentinelgo_update_tmp")

	if err := copyFile(newPath, tempPath); err != nil {
		return fmt.Errorf("copy to temp file failed: %w", err)
	}

	if err := os.Rename(tempPath, selfPath); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("atomic rename failed: %w", err)
	}

	_ = os.Remove(newPath)

	// #nosec G302 - Executable binaries need 0755 permissions
	if err := os.Chmod(selfPath, 0755); err != nil {
		return fmt.Errorf("set executable permissions failed: %w", err)
	}

	return nil
}

func copyFile(src, dst string) error {
	// #nosec G304 - src and dst are controlled paths for self-update
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = source.Close() }()

	// #nosec G304 - dst is a controlled path for self-update
	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = destination.Close() }()

	_, err = io.Copy(destination, source)
	return err
}

func removeFile(path string) error {
	return os.Remove(path)
}

// createBackup copies the running binary to <self>.backup and returns the path.
func createBackup() (string, error) {
	selfPath, err := os.Executable()
	if err != nil {
		return "", err
	}

	backupPath := selfPath + ".backup"

	// #nosec G304 - selfPath is a controlled path from os.Executable()
	src, err := os.Open(selfPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = src.Close() }()

	// #nosec G304 - backupPath is a controlled path
	dst, err := os.Create(backupPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = dst.Close() }()

	if _, err := io.Copy(dst, src); err != nil {
		if removeErr := os.Remove(backupPath); removeErr != nil {
			log.Printf("failed to remove backup file %s: %v", backupPath, removeErr)
		}
		return "", err
	}

	if info, err := os.Stat(selfPath); err == nil {
		if err := os.Chmod(backupPath, info.Mode()); err != nil {
			log.Printf("Warning: failed to set permissions on backup: %v", err)
		}
	}

	return backupPath, nil
}

// rollbackFromBackup restores the binary from backupPath using an atomic rename.
func rollbackFromBackup(backupPath string) error {
	selfPath, err := os.Executable()
	if err != nil {
		return err
	}

	if runtime.GOOS == "windows" {
		fmt.Printf("Cannot perform in-process rollback on Windows (file locked).\n")
		fmt.Printf("Backup preserved at: %s\n", backupPath)
		fmt.Printf("To manually restore: copy %s %s\n", backupPath, selfPath)
		return fmt.Errorf("in-process rollback not supported on Windows")
	}

	tempPath := selfPath + ".rollback"
	if err := copyFile(backupPath, tempPath); err != nil {
		return err
	}

	if err := os.Rename(tempPath, selfPath); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	fmt.Printf("Successfully rolled back from backup: %s\n", backupPath)
	return nil
}

// recodesignForGatekeeper re-signs the binary with an ad-hoc identity and
// registers its new CDHash with Gatekeeper. Must be called after every atomic
// replace on macOS: spctl --add stores the CDHash at install time, and the
// replaced binary has a completely different hash, so without this launchd
// cannot restart the updated binary (Gatekeeper rejects it silently).
func recodesignForGatekeeper(selfPath string) {
	_ = exec.Command("xattr", "-d", "com.apple.quarantine", selfPath).Run()
	_ = exec.Command("codesign", "--force", "--sign", "-", selfPath).Run()
	_ = exec.Command("spctl", "--add", selfPath).Run()
}

// restart hands control to the OS service manager so the new binary runs.
//
// On Linux/macOS the binary has ALREADY been replaced in place by atomicReplace
// before this is called, so we simply exit and let the service manager relaunch
// the (now-new) binary:
//   - macOS launchd has KeepAlive=true: it relaunches on any exit.
//   - Linux systemd has Restart=on-failure: it relaunches on a non-zero exit.
//
// On Windows a running .exe cannot be replaced in place, so the swap is deferred
// to a small script that waits for this process to exit, moves the new binary
// into place, and starts the service again via the SCM.
//
// The version is intentionally NOT persisted before this point: if the swap or
// relaunch fails, the old binary keeps running and its compiled-in version
// (config.Version) ensures the update is retried on the next check, rather than
// the agent silently reporting a version it isn't running.
func restart(newPath, backupPath string) error {
	selfPath, err := os.Executable()
	if err != nil {
		return err
	}

	if runtime.GOOS == "windows" {
		return restartWindows(newPath, selfPath, backupPath)
	}

	if runtime.GOOS == "darwin" {
		log.Println("Updater: update applied; exiting for launchd (KeepAlive) to relaunch the new binary")
		// Re-sign and re-register with Gatekeeper before exit. spctl --add stores
		// the binary's CDHash in the policy DB; after atomicReplace the CDHash has
		// changed, so the old install-time entry no longer matches. Without this,
		// launchd relaunches the new binary but Gatekeeper rejects it and the
		// daemon silently never comes back up.
		recodesignForGatekeeper(selfPath)
		os.Exit(0)
		return nil
	}

	// Linux and other systemd-managed platforms: a non-zero exit triggers
	// Restart=on-failure, relaunching the replaced binary.
	log.Println("Updater: update applied; exiting for systemd (Restart=on-failure) to relaunch the new binary")
	os.Exit(1)
	return nil
}

// restartWindows defers the binary swap to a script because the running .exe is
// locked. The script waits for this process to exit, replaces the binary with a
// retry loop (the file unlocks only once we exit), then restarts the service via
// the SCM. `timeout` is avoided: it fails in non-interactive Session 0 with
// "Input redirection is not supported"; `ping` provides the delay instead.
func restartWindows(newPath, selfPath, backupPath string) error {
	dir := filepath.Dir(selfPath)
	bat := filepath.Join(dir, "sentinelgo_update.bat")
	failureMarker := filepath.Join(dir, "sentinelgo_update_failure.txt")

	script := windowsUpdateScript(newPath, selfPath, backupPath, bat, failureMarker)

	// #nosec G306 - the update script must be executable/readable by the system
	if err := os.WriteFile(bat, []byte(script), 0644); err != nil {
		return fmt.Errorf("write update script: %w", err)
	}

	// Lock the script down to SYSTEM/Administrators/owner so a standard user
	// cannot tamper with it during the window before it runs (it executes with
	// the service's privileges).
	if err := winsec.SecurePath(bat); err != nil {
		log.Printf("Updater: warning – failed to secure update script ACL: %v", err)
	}

	// #nosec G204 - bat is a controlled path generated above
	cmd := exec.Command("cmd", "/c", "start", "/b", "", bat)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launch update script: %w", err)
	}

	log.Println("Updater: update staged; exiting so the SCM can restart the service with the new binary")
	os.Exit(0)
	return nil
}

// windowsUpdateScript performs a bounded swap, requires five consecutive SCM
// RUNNING observations, and restores the known-good binary on any failure. The
// marker contains no command output or configuration data and is safe to ship
// as an operational signal on the next startup.
func windowsUpdateScript(newPath, selfPath, backupPath, bat, failureMarker string) string {
	return fmt.Sprintf(`@echo off
setlocal
ping -n 3 127.0.0.1 >nul
set SWAP_ATTEMPTS=0
:swap_retry
move /Y "%s" "%s" >nul 2>&1
if errorlevel 1 (
  set /a SWAP_ATTEMPTS+=1
  if %%SWAP_ATTEMPTS%% GEQ 30 goto rollback
  ping -n 2 127.0.0.1 >nul
  goto swap_retry
)
sc start "%s" >nul 2>&1
set HEALTH_ATTEMPTS=0
set HEALTHY_COUNT=0
:health_check
ping -n 3 127.0.0.1 >nul
sc query "%s" | find "RUNNING" >nul 2>&1
if errorlevel 1 (set HEALTHY_COUNT=0) else (set /a HEALTHY_COUNT+=1)
if %%HEALTHY_COUNT%% GEQ 5 goto success
set /a HEALTH_ATTEMPTS+=1
if %%HEALTH_ATTEMPTS%% GEQ 30 goto rollback
goto health_check

:rollback
sc stop "%s" >nul 2>&1
ping -n 3 127.0.0.1 >nul
copy /Y "%s" "%s" >nul 2>&1
if errorlevel 1 goto rollback_failed
sc start "%s" >nul 2>&1
set ROLLBACK_ATTEMPTS=0
set ROLLBACK_HEALTHY=0
:rollback_health
ping -n 3 127.0.0.1 >nul
sc query "%s" | find "RUNNING" >nul 2>&1
if errorlevel 1 (set ROLLBACK_HEALTHY=0) else (set /a ROLLBACK_HEALTHY+=1)
if %%ROLLBACK_HEALTHY%% GEQ 5 goto rollback_success
set /a ROLLBACK_ATTEMPTS+=1
if %%ROLLBACK_ATTEMPTS%% GEQ 30 goto rollback_failed
goto rollback_health

:rollback_success
>"%s" echo update_failed_rolled_back
del "%s" >nul 2>&1
exit /b 1

:rollback_failed
>"%s" echo update_failed_rollback_failed
exit /b 2

:success
del "%s" >nul 2>&1
del "%s" >nul 2>&1
del "%s" >nul 2>&1
exit /b 0
`, newPath, selfPath, windowsServiceName, windowsServiceName, windowsServiceName,
		backupPath, selfPath, windowsServiceName, windowsServiceName, failureMarker, bat, failureMarker,
		backupPath, failureMarker, bat)
}
