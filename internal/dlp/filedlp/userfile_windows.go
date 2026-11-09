package filedlp

// The service's side of shares and sync folders (#330): a session helper
// hands over a file it opened as the user (userfolders_windows.go). The
// service duplicates the handle out of the helper's process (it runs as
// SYSTEM, so it may), and from then on works only with its own handle:
//
//   - what the file is comes from the handle (its final path, identity and
//     attributes), never from the helper's message: a user can only make
//     the service look at a file they opened themselves;
//   - the duplicate has no more access than the helper's handle, so
//     remediation can only remove what the user could remove anyway;
//   - a network share's server and share come from the handle's UNC path,
//     and trusted shares are skipped.

import (
	"errors"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"sentinelgo/internal/dlp/ipc"
	"sentinelgo/internal/dlp/policy"
)

// Test seam: duplicating a handle out of a helper's process.
var duplicateFrom = func(pid uint32, h windows.Handle) (windows.Handle, error) {
	src, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, pid)
	if err != nil {
		return 0, err
	}
	defer func() { _ = windows.CloseHandle(src) }()
	var dup windows.Handle
	err = windows.DuplicateHandle(src, h, windows.CurrentProcess(), &dup, 0, false, windows.DUPLICATE_SAME_ACCESS)
	return dup, err
}

// fileNameNormalized is GetFinalPathNameByHandle's FILE_NAME_NORMALIZED.
const (
	fileNameNormalized = 0x0
	volumeNameDOS      = 0x0 // VOLUME_NAME_DOS
)

// errNotTaken: the handed-over file isn't one this enforcer decides.
var errNotTaken = errors.New("file not taken")

// TakeUserFile takes a file a session helper handed over and queues it for
// a decision. It runs on the helper's read loop: it only duplicates the
// handle and queues; the hub acks the helper afterwards.
func (e *windowsEnforcer) TakeUserFile(from ipc.Identity, f ipc.UserFile) {
	r, err := e.userRequest(from, f)
	if err != nil {
		return
	}
	select {
	case e.queue <- r:
	default:
		_ = r.File.Close()
		e.dropped.Add(1)
	}
}

func (e *windowsEnforcer) userRequest(from ipc.Identity, f ipc.UserFile) (Request, error) {
	e.mu.Lock()
	running := e.running
	e.mu.Unlock()
	c := e.compiled.Load()
	if !running || e.localOff.Load() || c == nil || from.PID <= 0 {
		return Request{}, errNotTaken
	}
	files := c.Modules.Files
	if (f.Channel != policy.ChannelFileNetworkShare && f.Channel != policy.ChannelFileCloudSync) ||
		!files.ChannelEnabled(f.Channel) || !files.CopyCorrelation.ScansOnClose() {
		return Request{}, errNotTaken
	}
	h, err := duplicateFrom(uint32(from.PID), windows.Handle(f.Handle)) // #nosec G115 -- a PID and a handle value from the helper
	if err != nil {
		e.unreadable.Add(1)
		return Request{}, errNotTaken
	}
	r, err := userFileRequest(h, from, f, files)
	if err != nil {
		_ = windows.CloseHandle(h)
		return Request{}, err
	}
	return r, nil
}

// userFileRequest builds the Request for the service's own handle h.
func userFileRequest(h windows.Handle, from ipc.Identity, f ipc.UserFile, files policy.FilesModule) (Request, error) {
	if !decidable(h) {
		return Request{}, errNotTaken
	}
	id, err := handleIdentity(h)
	if err != nil {
		return Request{}, errNotTaken
	}
	path, err := finalPath(h)
	if err != nil {
		return Request{}, errNotTaken
	}
	dest, ok := userDestination(path, f)
	if !ok || TrustedShare(files.TrustedShares, dest) {
		return Request{}, errNotTaken
	}
	return Request{File: os.NewFile(uintptr(h), path), Path: path, Dest: dest,
		Proc: Process{UID: from.SessionID, User: from.User}, Ident: id, At: time.Now()}, nil
}

// finalPath is the handle's path: \\server\share\… for a share, C:\… for a
// local file.
func finalPath(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), fileNameNormalized|volumeNameDOS)
	if err != nil {
		return "", err
	}
	if int(n) > len(buf) {
		return "", errors.New("path too long")
	}
	return cleanFinalPath(windows.UTF16ToString(buf[:n])), nil
}

// cleanFinalPath drops the \\?\ prefix: \\?\UNC\server\share\x becomes
// \\server\share\x, \\?\C:\x becomes C:\x.
func cleanFinalPath(p string) string {
	if rest, ok := strings.CutPrefix(p, `\\?\UNC\`); ok {
		return `\\` + rest
	}
	return strings.TrimPrefix(p, `\\?\`)
}

// userDestination describes where a handed-over file is. A share must be a
// UNC path (the handle says so, whatever the helper claimed); a sync folder
// must be a local path.
func userDestination(path string, f ipc.UserFile) (Destination, bool) {
	label := boundLabel(f.Label)
	if f.Channel == policy.ChannelFileNetworkShare {
		rest, ok := strings.CutPrefix(path, `\\`)
		if !ok {
			return Destination{}, false
		}
		parts := strings.SplitN(rest, `\`, 3)
		if len(parts) < 3 || parts[0] == "" || parts[1] == "" {
			return Destination{}, false
		}
		share := `\\` + parts[0] + `\` + parts[1]
		return Destination{Channel: f.Channel, Type: TypeNetworkShare, Mount: share, Source: share, ShareHost: parts[0]}, true
	}
	if len(path) < 3 || path[1] != ':' {
		return Destination{}, false
	}
	return Destination{Channel: f.Channel, Type: TypeCloudSync, Mount: path[:3], VolumeLabel: label}, true
}

// boundLabel keeps the helper's label for display only, short and plain.
func boundLabel(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}
