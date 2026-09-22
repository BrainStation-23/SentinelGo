package updater

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"sentinelgo/internal/paths"
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

// createBackup copies the running binary into the staging directory and returns
// the path.
//
// The copy is a complete, runnable agent binary, so it needs the same protection
// as the binary itself: it previously sat next to the executable with whatever
// permissions it inherited, in a directory a standard user could write, while
// every other update artifact was ACL'd. An attacker-controlled "backup" is a
// straightforward way to get privileged code executed by an operator following
// the rollback instructions.
func createBackup() (string, error) {
	selfPath, err := os.Executable()
	if err != nil {
		return "", err
	}

	stagingDir := paths.StagingDir()
	if err := os.MkdirAll(stagingDir, 0700); err != nil {
		return "", fmt.Errorf("create staging directory: %w", err)
	}
	if err := winsec.SecureSystemPath(stagingDir); err != nil {
		return "", fmt.Errorf("refusing to back up: cannot secure staging directory %s: %w",
			stagingDir, err)
	}

	backupPath := filepath.Join(stagingDir, filepath.Base(selfPath)+".backup")

	// #nosec G304 - selfPath is a controlled path from os.Executable()
	src, err := os.Open(selfPath)
	if err != nil {
		return "", err
	}
	defer func() { _ = src.Close() }()

	// A stale backup from a previous update would make CreateSecureFile fail,
	// since it refuses to adopt an existing file.
	if err := os.Remove(backupPath); err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("remove stale backup %s: %w", backupPath, err)
	}

	dst, err := winsec.CreateSecureFile(backupPath)
	if err != nil {
		return "", fmt.Errorf("create secure backup: %w", err)
	}
	defer func() { _ = dst.Close() }()

	if _, err := io.Copy(dst, src); err != nil {
		if removeErr := os.Remove(backupPath); removeErr != nil {
			log.Printf("failed to remove backup file %s: %v", backupPath, removeErr)
		}
		return "", err
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
func restart(newPath string) error {
	selfPath, err := os.Executable()
	if err != nil {
		return err
	}

	if runtime.GOOS == "windows" {
		return restartWindows(newPath, selfPath)
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

// restartWindows swaps the binary in-process and exits so the SCM restarts the
// service on the new image.
//
// It replaces a generated .bat that was written into the install directory and
// launched through cmd.exe. See replaceRunningBinary in swap_windows.go for why
// that artifact was worth removing.
//
// Exiting non-zero is what triggers the restart: the SCM applies the service's
// configured failure actions when the process dies without reporting
// SERVICE_STOPPED. That makes recovery actions a hard prerequisite, not a nicety
// -- without them "exit to update" means "exit and stay down". Both installation
// paths configure them (install.bat via `sc failure`, the Go -install path via
// SetRecoveryActions).
//
// If the swap could only be scheduled for the next reboot, this does NOT exit:
// the currently-running old binary is still a working agent, and restarting into
// a binary that has not been replaced yet would just repeat the update on every
// start.
func restartWindows(newPath, selfPath string) error {
	outcome, err := replaceRunningBinary(newPath, selfPath)
	if err != nil {
		return err
	}

	if outcome == swapDeferred {
		log.Println("Updater: update will be applied on the next reboot; continuing on the current version")
		return nil
	}

	log.Println("Updater: binary replaced; exiting so the SCM restarts the service on the new version")
	os.Exit(1)
	return nil
}
