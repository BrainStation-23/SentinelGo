package filedlp

// Network shares opened by path, without a drive letter (#428). Mapped
// drives are listed by mappedDrives; a user who opens \\server\share in
// Explorer, or saves to it from an app, uses no drive letter. The helper
// learns those shares, as the user, from:
//
//   - the session's live connections (WNetOpenEnum, RESOURCE_CONNECTED),
//     with or without a drive letter;
//   - remembered mappings (HKCU\Network\<letter>\RemotePath), connected or
//     not;
//   - shares Explorer has opened (HKCU\…\Explorer\MountPoints2, keys named
//     ##server#share).
//
// Each is watched like a mapped drive, at most maxUNCWatches of them, live
// connections first. A share a drive is mapped to is watched through the
// drive only. Trusted shares are skipped by the watcher (reconcile), and a
// watch that can't start or goes away is retried after rootRetry.

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"sentinelgo/internal/dlp/policy"
)

// maxUNCWatches bounds the shares watched by path.
const maxUNCWatches = 16

const (
	resourceConnected = 1 // RESOURCE_CONNECTED
	resourceTypeDisk  = 1 // RESOURCETYPE_DISK

	networkKey      = `Network`
	mountPoints2Key = `Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`
)

var (
	procWNetOpenEnumW     = mpr.NewProc("WNetOpenEnumW")
	procWNetEnumResourceW = mpr.NewProc("WNetEnumResourceW")
	procWNetCloseEnum     = mpr.NewProc("WNetCloseEnum")
)

// uncShareSources are where shares without a drive letter are learned
// from; replaced in tests.
type uncShareSources struct {
	connected  func() []string // live connections
	persistent func() []string // remembered mappings
	recent     func() []string // shares Explorer has opened
}

// Test seam: the sources shareRoots reads.
var uncSources = uncShareSources{connected: connectedShares, persistent: persistentShares, recent: recentShares}

// shareRoots are the user's network shares: mapped drives, then shares
// opened by path.
func shareRoots() []userRoot {
	drives := mappedDrives()
	return append(drives, uncShares(uncSources, drives)...)
}

// uncShares lists the \\server\share roots to watch, live connections
// first, at most maxUNCWatches, leaving out those a drive is mapped to.
func uncShares(src uncShareSources, drives []userRoot) []userRoot {
	seen := map[string]bool{}
	for _, d := range drives {
		seen[strings.ToLower(d.label)] = true
	}
	var out []userRoot
	for _, list := range []func() []string{src.connected, src.persistent, src.recent} {
		if list == nil {
			continue
		}
		for _, s := range list() {
			unc, ok := normalizeUNC(s)
			if !ok || seen[strings.ToLower(unc)] {
				continue
			}
			if len(out) >= maxUNCWatches {
				return out
			}
			seen[strings.ToLower(unc)] = true
			out = append(out, uncRoot(unc))
		}
	}
	return out
}

func uncRoot(unc string) userRoot {
	host, _, _ := strings.Cut(unc[2:], `\`)
	return userRoot{path: unc + `\`, label: unc,
		dest: Destination{Channel: policy.ChannelFileNetworkShare, Type: TypeNetworkShare, Mount: unc, Source: unc, ShareHost: host}}
}

// normalizeUNC reduces a path on a share to its \\server\share root.
// Device paths (\\?\, \\.\) and anything without both a server and a share
// are not shares.
func normalizeUNC(s string) (string, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), `\\`)
	if !ok {
		return "", false
	}
	parts := strings.SplitN(rest, `\`, 3)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" || parts[0] == "?" || parts[0] == "." {
		return "", false
	}
	return `\\` + parts[0] + `\` + parts[1], true
}

// mountPointShare is the share a MountPoints2 key names: ##server#share
// stands for \\server\share. Other keys (volume GUIDs, drive letters) are
// not shares.
func mountPointShare(name string) (string, bool) {
	rest, ok := strings.CutPrefix(name, "##")
	if !ok {
		return "", false
	}
	return normalizeUNC(`\\` + strings.ReplaceAll(rest, "#", `\`))
}

// netResource is NETRESOURCEW.
type netResource struct {
	Scope, Type, DisplayType, Usage          uint32
	LocalName, RemoteName, Comment, Provider *uint16
}

// connectedShares lists the remote names of the session's live disk
// connections, with or without a drive letter.
func connectedShares() []string {
	var h windows.Handle
	if r, _, _ := procWNetOpenEnumW.Call(resourceConnected, resourceTypeDisk, 0, 0, uintptr(unsafe.Pointer(&h))); r != 0 {
		return nil
	}
	defer func() { _, _, _ = procWNetCloseEnum.Call(uintptr(h)) }()
	buf := make([]uint64, 2048) // 16 KiB, pointer-aligned
	var out []string
	for range 64 { // bounded: a session has a handful of connections
		count := ^uint32(0)          // as many as fit
		size := uint32(len(buf) * 8) // #nosec G115 -- a small buffer
		r, _, _ := procWNetEnumResourceW.Call(uintptr(h), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
		switch windows.Errno(r) {
		case 0:
		case windows.ERROR_MORE_DATA: // one entry needs more room: size says how much
			buf = make([]uint64, size/8+1)
			continue
		default: // ERROR_NO_MORE_ITEMS, or an error
			return out
		}
		for _, nr := range unsafe.Slice((*netResource)(unsafe.Pointer(&buf[0])), count) {
			if nr.RemoteName != nil {
				out = append(out, windows.UTF16PtrToString(nr.RemoteName))
			}
		}
	}
	return out
}

// persistentShares lists the remembered mappings' remote paths.
func persistentShares() []string {
	k, err := registry.OpenKey(registry.CURRENT_USER, networkKey, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer func() { _ = k.Close() }()
	names, _ := k.ReadSubKeyNames(-1)
	var out []string
	for _, n := range names {
		sk, err := registry.OpenKey(k, n, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		if v, _, err := sk.GetStringValue("RemotePath"); err == nil {
			out = append(out, v)
		}
		_ = sk.Close()
	}
	return out
}

// recentShares lists the shares Explorer has opened.
func recentShares() []string {
	k, err := registry.OpenKey(registry.CURRENT_USER, mountPoints2Key, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer func() { _ = k.Close() }()
	names, _ := k.ReadSubKeyNames(-1)
	var out []string
	for _, n := range names {
		if unc, ok := mountPointShare(n); ok {
			out = append(out, unc)
		}
	}
	return out
}
