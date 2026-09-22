//go:build windows

package updater

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/sys/windows"
)

// swapOutcome describes what replaceRunningBinary managed to do.
type swapOutcome int

const (
	// swapDone means the new binary is in place and a restart will load it.
	swapDone swapOutcome = iota
	// swapDeferred means the rename is queued for the next reboot. The old
	// binary keeps running until then, which is a working agent on an old
	// version -- strictly better than a dead one.
	swapDeferred
)

// replaceRunningBinary puts newPath in place of the currently running
// executable.
//
// Windows forbids overwriting a running image but permits *renaming* it: the
// loader opens the image with FILE_SHARE_DELETE, and a rename needs only DELETE
// access. So the running binary is moved aside and the staged one takes its
// name. This is how self-updating Windows programs generally work.
//
// It replaces an earlier approach that wrote a .bat into the install directory
// and launched it through cmd.exe. That script was an executable artifact living
// beside the binary, created with default permissions and only ACL'd afterwards,
// and it ran with the service's LocalSystem privileges -- a file worth planting,
// in the exact directory that a standard user could already write. Doing the
// rename in-process removes the artifact, the shell invocation, and the window
// between the two.
func replaceRunningBinary(newPath, selfPath string) (swapOutcome, error) {
	oldPath := selfPath + ".old"

	// A leftover .old from a previous update would block the rename.
	if err := os.Remove(oldPath); err != nil && !os.IsNotExist(err) {
		log.Printf("Updater: could not remove stale %s: %v", oldPath, err)
	}

	if err := moveFile(selfPath, oldPath, windows.MOVEFILE_REPLACE_EXISTING); err != nil {
		// Something holds the image with a share mode that forbids renaming --
		// most often real-time antivirus. Fall back to a reboot-time rename,
		// which the Session Manager performs before anything else starts.
		return deferToReboot(newPath, selfPath, err)
	}

	if err := moveFile(newPath, selfPath,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		// Put the original back before giving up; otherwise the service has no
		// binary at all and will not start.
		if restoreErr := moveFile(oldPath, selfPath, windows.MOVEFILE_REPLACE_EXISTING); restoreErr != nil {
			return swapDone, fmt.Errorf(
				"move staged binary into place failed (%w) AND restoring the original from %s failed (%v): "+
					"the service binary is missing and needs manual recovery",
				err, oldPath, restoreErr)
		}
		return swapDone, fmt.Errorf("move staged binary into place: %w", err)
	}

	// The old image is still mapped by this process, so it cannot be deleted
	// yet. Queue it: PendingFileRenameOperations lives in a registry key only
	// administrators can write.
	if err := moveFile(oldPath, "", windows.MOVEFILE_DELAY_UNTIL_REBOOT); err != nil {
		log.Printf("Updater: could not schedule %s for removal: %v", oldPath, err)
	}

	return swapDone, nil
}

// deferToReboot queues the swap for the next boot and reports why.
func deferToReboot(newPath, selfPath string, cause error) (swapOutcome, error) {
	if err := moveFile(newPath, selfPath,
		windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_DELAY_UNTIL_REBOOT); err != nil {
		return swapDone, fmt.Errorf("rename running binary failed (%w) and scheduling a "+
			"reboot-time replacement also failed: %v", cause, err)
	}
	log.Printf("Updater: could not rename the running binary (%v); the update is staged "+
		"and will be applied on the next reboot", cause)
	return swapDeferred, nil
}

// moveFile wraps MoveFileEx. An empty destination means "delete", which is only
// meaningful together with MOVEFILE_DELAY_UNTIL_REBOOT.
func moveFile(from, to string, flags uint32) error {
	fromPtr, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}

	var toPtr *uint16
	if to != "" {
		toPtr, err = windows.UTF16PtrFromString(to)
		if err != nil {
			return err
		}
	}

	return windows.MoveFileEx(fromPtr, toPtr, flags)
}
