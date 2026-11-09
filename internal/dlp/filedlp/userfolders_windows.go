package filedlp

// Network shares and cloud sync folders on Windows (#330). They belong to
// the user's logon session: SYSTEM doesn't see a user's mapped drives, and
// can't reach a share without the user's credentials. So these two channels
// run in the session helper, as the user:
//
//   - file.network_share watches the user's mapped network drives (drive
//     letters that are DRIVE_REMOTE in the user's session);
//   - file.cloud_sync watches the user's OneDrive, Dropbox, Box and iCloud
//     Drive folders, and a Google Drive for desktop volume.
//
// A written file is opened as the user once it is quiet (openForDecision)
// and its handle is handed to the service (the sink's HandOff), which
// duplicates it, decides, and remediates through it. The helper never scans
// and never sends content. Trusted shares are skipped in the helper too.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/ipc"
	"sentinelgo/internal/dlp/policy"
)

// UserFileSink is what the helper's event sink offers to these channels
// (session.FileHandoff): hand an open file to the service; release closes
// it.
type UserFileSink interface {
	HandOff(f ipc.UserFile, release func())
}

// userRoot is one watched drive or folder.
type userRoot struct {
	path  string // Z:\ or C:\Users\ann\OneDrive\
	label string // \\server\share, "OneDrive", …
	dest  Destination
}

// Test seams: how the roots are found, and how often.
var (
	findShareRoots = mappedDrives
	findSyncRoots  = syncFolders
	rootsPoll      = 5 * time.Second
)

// UserFolderChannels are the helper's file channels on Windows.
func UserFolderChannels() []channel.Channel {
	return []channel.Channel{userFolders{name: policy.ChannelFileNetworkShare}, userFolders{name: policy.ChannelFileCloudSync}}
}

type userFolders struct{ name string }

func (u userFolders) Name() string { return u.name }

func (userFolders) Supported() channel.Capability { return channel.Supported() }

// Run watches the channel's roots until ctx ends.
func (u userFolders) Run(ctx context.Context, c *policy.Compiled, sink channel.EventSink) error {
	hand, ok := sink.(UserFileSink)
	if !ok || c == nil || !c.Modules.Files.Enabled || !c.Modules.Files.CopyCorrelation.ScansOnClose() {
		return channel.ErrUnsupported
	}
	w := &userWatcher{name: u.name, files: c.Modules.Files, hand: hand, watches: map[string]*dirWatch{},
		changes: make(chan fsChange, changeQueueSize)}
	defer w.closeAll()
	var dropped, unreadable atomic.Uint64
	pending := newPendingSet(&dropped, &unreadable)
	roots := time.NewTicker(rootsPoll)
	defer roots.Stop()
	tick := time.NewTicker(pendingTick)
	defer tick.Stop()
	w.reconcile()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-roots.C:
			w.reconcile()
		case ch := <-w.changes:
			pending.add(ch, time.Now())
		case now := <-tick.C:
			pending.due(now, func(path string, _ time.Time) (Request, openStatus) {
				return w.handOff(path, &unreadable)
			}, nil)
		}
	}
}

type userWatcher struct {
	name    string
	files   policy.FilesModule
	hand    UserFileSink
	watches map[string]*dirWatch
	roots   map[string]userRoot
	changes chan fsChange
}

// reconcile watches the roots there are now and stops watching the rest.
func (w *userWatcher) reconcile() {
	want := map[string]userRoot{}
	find := findSyncRoots
	if w.name == policy.ChannelFileNetworkShare {
		find = findShareRoots
	}
	for _, r := range find() {
		if w.name == policy.ChannelFileNetworkShare && TrustedShare(w.files.TrustedShares, r.dest) {
			continue
		}
		want[strings.ToLower(r.path)] = r
	}
	for key, dw := range w.watches {
		if _, ok := want[key]; !ok {
			dw.close()
			delete(w.watches, key)
		}
	}
	for key, r := range want {
		if _, ok := w.watches[key]; ok {
			continue
		}
		changes := w.changes
		dw, err := startWatch(r.path,
			func(ch fsChange) {
				select {
				case changes <- ch:
				default:
				}
			},
			func(root string) {
				select {
				case changes <- fsChange{root: root}:
				default:
				}
			},
			func(string) {})
		if err == nil {
			w.watches[key] = dw
		}
	}
	w.roots = want
}

func (w *userWatcher) closeAll() {
	for key, dw := range w.watches {
		dw.close()
		delete(w.watches, key)
	}
}

// handOff opens a quiet file as the user and hands it to the service. It
// never queues a Request: the pending set's queue is unused here.
func (w *userWatcher) handOff(path string, unreadable *atomic.Uint64) (Request, openStatus) {
	root, ok := w.rootOf(path)
	if !ok {
		return Request{}, openSkip
	}
	h, _, st := openForDecision(path, unreadable)
	if st != openOK {
		return Request{}, st
	}
	w.hand.HandOff(ipc.UserFile{Handle: uint64(h), Channel: w.name, Root: root.path, Label: root.label},
		func() { _ = windows.CloseHandle(h) })
	return Request{}, openSkip // handed over: nothing left for the pending set
}

func (w *userWatcher) rootOf(path string) (userRoot, bool) {
	lower := strings.ToLower(path)
	for key, r := range w.roots {
		root := strings.TrimSuffix(key, `\`) + `\`
		if strings.HasPrefix(lower, root) {
			return r, true
		}
	}
	return userRoot{}, false
}

var (
	mpr                    = windows.NewLazySystemDLL("mpr.dll")
	procWNetGetConnectionW = mpr.NewProc("WNetGetConnectionW")
)

const driveRemote = 4

// mappedDrives lists the session's mapped network drives.
func mappedDrives() []userRoot {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	var out []userRoot
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		letter := string(rune('A'+i)) + ":"
		rp, _ := windows.UTF16PtrFromString(letter + `\`)
		if windows.GetDriveType(rp) != driveRemote {
			continue
		}
		unc := uncOf(letter)
		if unc == "" {
			continue
		}
		host, _, _ := strings.Cut(strings.TrimPrefix(unc, `\\`), `\`)
		out = append(out, userRoot{path: letter + `\`, label: unc,
			dest: Destination{Channel: policy.ChannelFileNetworkShare, Type: TypeNetworkShare, Mount: letter + `\`, Source: unc, ShareHost: host}})
	}
	return out
}

// uncOf is the \\server\share a drive letter is mapped to.
func uncOf(letter string) string {
	lp, _ := windows.UTF16PtrFromString(letter)
	buf := make([]uint16, 1024)
	n := uint32(len(buf))
	if r, _, _ := procWNetGetConnectionW.Call(uintptr(unsafe.Pointer(lp)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n))); r != 0 {
		return ""
	}
	return windows.UTF16ToString(buf)
}

// syncFolders lists the user's sync client folders that exist.
func syncFolders() []userRoot {
	var out []userRoot
	add := func(path, label string) {
		if path == "" {
			return
		}
		if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
			return
		}
		p := strings.TrimSuffix(filepath.Clean(path), `\`) + `\`
		for _, r := range out {
			if strings.EqualFold(r.path, p) {
				return
			}
		}
		out = append(out, userRoot{path: p, label: label,
			dest: Destination{Channel: policy.ChannelFileCloudSync, Type: TypeCloudSync, Mount: p, VolumeLabel: label}})
	}
	for _, p := range oneDriveFolders() {
		add(p, "OneDrive")
	}
	for _, p := range dropboxFolders() {
		add(p, "Dropbox")
	}
	if home, err := os.UserHomeDir(); err == nil {
		add(filepath.Join(home, "Box"), "Box")
		add(filepath.Join(home, "iCloudDrive"), "iCloud Drive")
	}
	for _, p := range labelledVolumes("Google Drive") {
		add(p, "Google Drive")
	}
	return out
}

// oneDriveFolders reads each OneDrive account's folder (personal and work).
func oneDriveFolders() []string {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\OneDrive\Accounts`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer func() { _ = k.Close() }()
	names, _ := k.ReadSubKeyNames(-1)
	var out []string
	for _, n := range names {
		ak, err := registry.OpenKey(k, n, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		if v, _, err := ak.GetStringValue("UserFolder"); err == nil {
			out = append(out, v)
		}
		_ = ak.Close()
	}
	return out
}

// dropboxFolders reads Dropbox's info.json (personal and business).
func dropboxFolders() []string {
	var out []string
	for _, env := range []string{"LOCALAPPDATA", "APPDATA"} {
		b, err := os.ReadFile(filepath.Join(os.Getenv(env), "Dropbox", "info.json")) // #nosec G304 -- the user's own Dropbox settings
		if err != nil {
			continue
		}
		var info map[string]struct {
			Path string `json:"path"`
		}
		if json.Unmarshal(b, &info) != nil {
			continue
		}
		for _, acct := range info {
			out = append(out, acct.Path)
		}
	}
	return out
}

// labelledVolumes lists drive roots whose volume label is label (Google
// Drive for desktop mounts as a drive called "Google Drive").
func labelledVolumes(label string) []string {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil
	}
	var out []string
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		root := string(rune('A'+i)) + `:\`
		rp, _ := windows.UTF16PtrFromString(root)
		if windows.GetDriveType(rp) != driveFixed {
			continue // never ask a network drive: a disconnected one can hang
		}
		var name [windows.MAX_PATH + 1]uint16
		if windows.GetVolumeInformation(rp, &name[0], uint32(len(name)), nil, nil, nil, nil, 0) == nil &&
			strings.EqualFold(windows.UTF16ToString(name[:]), label) {
			out = append(out, root)
		}
	}
	return out
}
