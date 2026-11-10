package filedlp

// Which mounts are removable media or network shares on macOS (#332). The
// mount table comes from getfsstat (x/sys/unix). A local volume under
// /Volumes is classified once per mount with `diskutil info -plist` (bus
// protocol, internal or not), and a USB drive's vendor, product and serial
// come from `ioreg`: the OS's own tools as subprocesses, no frameworks and
// no cgo.

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"sentinelgo/internal/dlp/policy"
)

// macVolume is a monitored mount.
type macVolume struct {
	Destination
	ReadOnly bool
}

// Test seams: the mount table, diskutil and ioreg.
var (
	listVolumes = macVolumes
	runDiskutil = func(ctx context.Context, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, "/usr/sbin/diskutil", args...).Output() // #nosec G204 -- fixed tool; device names from the mount table
	}
	runIoreg = func(ctx context.Context) ([]byte, error) {
		return exec.CommandContext(ctx, "/usr/sbin/ioreg", "-a", "-l", "-r", "-c", "IOUSBHostDevice").Output()
	}
	getfsstat = func() []unix.Statfs_t {
		n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
		if err != nil || n <= 0 {
			return nil
		}
		buf := make([]unix.Statfs_t, n+8)
		n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT)
		if err != nil {
			return nil
		}
		return buf[:n]
	}
)

const toolTimeout = 10 * time.Second

// networkFSDarwin are the network file systems.
var networkFSDarwin = map[string]bool{"smbfs": true, "nfs": true, "afpfs": true, "webdav": true}

var (
	diskCacheMu sync.Mutex
	diskCache   = map[string]diskInfo{} // device + mount point → what diskutil said
)

// macVolumes lists the removable volumes and network shares mounted now.
func macVolumes() []macVolume {
	var out []macVolume
	seen := map[string]bool{}
	for _, st := range getfsstat() {
		mnt := unix.ByteSliceToString(st.Mntonname[:])
		from := unix.ByteSliceToString(st.Mntfromname[:])
		fstype := unix.ByteSliceToString(st.Fstypename[:])
		ro := st.Flags&unix.MNT_RDONLY != 0
		if networkFSDarwin[fstype] {
			out = append(out, macVolume{Destination: Destination{Channel: policy.ChannelFileNetworkShare, Type: TypeNetworkShare,
				Mount: mnt, Source: from, ShareHost: shareHostDarwin(from)}, ReadOnly: ro})
			continue
		}
		if !strings.HasPrefix(mnt, "/Volumes/") || !strings.HasPrefix(from, "/dev/disk") {
			continue
		}
		key := from + "\x00" + mnt
		seen[key] = true
		info, ok := cachedDisk(key, from)
		if !ok || !info.Removable {
			continue
		}
		out = append(out, macVolume{Destination: Destination{Channel: policy.ChannelFileRemovable, Type: TypeRemovable,
			Mount: mnt, Source: from, VolumeLabel: mnt[len("/Volumes/"):], USB: info.USB}, ReadOnly: ro || info.ReadOnly})
	}
	diskCacheMu.Lock()
	for k := range diskCache {
		if !seen[k] {
			delete(diskCache, k) // unmounted: classified again next time
		}
	}
	diskCacheMu.Unlock()
	return out
}

func cachedDisk(key, dev string) (diskInfo, bool) {
	diskCacheMu.Lock()
	info, ok := diskCache[key]
	diskCacheMu.Unlock()
	if ok {
		return info, true
	}
	info, err := describeDisk(dev)
	if err != nil {
		return diskInfo{}, false // tried again on the next pass
	}
	diskCacheMu.Lock()
	diskCache[key] = info
	diskCacheMu.Unlock()
	return info, true
}

// describeDisk asks diskutil about dev and, for USB, ioreg for its ids.
func describeDisk(dev string) (diskInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), toolTimeout)
	defer cancel()
	out, err := runDiskutil(ctx, "info", "-plist", dev)
	if err != nil {
		return diskInfo{}, fmt.Errorf("diskutil info: %w", err)
	}
	info, err := parseDiskutilInfo(out)
	if err != nil {
		return diskInfo{}, err
	}
	if info.Removable && info.WholeDisk != "" {
		if usb, err := runIoreg(ctx); err == nil {
			info.USB = usbForDisk(usb, info.WholeDisk)
		}
	}
	return info, nil
}
