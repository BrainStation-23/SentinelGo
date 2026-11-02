package filedlp

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/policy"
)

// Roots for sysfs and /dev; tests point them at fixtures.
var (
	sysRoot = "/sys"
	devRoot = "/dev"
)

// mountInfo is one line of /proc/self/mountinfo.
type mountInfo struct {
	ID         int
	MajMin     string
	MountPoint string
	FSType     string
	Source     string
}

// parseMountinfo reads /proc/<pid>/mountinfo. Malformed lines are skipped.
func parseMountinfo(r io.Reader) []mountInfo {
	var out []mountInfo
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		sep := -1
		for i, f := range fields {
			if f == "-" {
				sep = i
				break
			}
		}
		if sep < 6 || len(fields) < sep+3 {
			continue
		}
		id, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		out = append(out, mountInfo{
			ID: id, MajMin: fields[2], MountPoint: unescapeMount(fields[4]),
			FSType: fields[sep+1], Source: unescapeMount(fields[sep+2]),
		})
	}
	return out
}

// unescapeMount decodes the octal escapes (\040 for a space) mountinfo uses.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// networkFS maps network filesystem types to how their source names the host.
var networkFS = map[string]bool{"cifs": true, "smb3": true, "smbfs": true, "nfs": true, "nfs4": true, "fuse.sshfs": true}

// systemMounts are never destinations, nor anything under them.
var systemMounts = []string{"/proc", "/sys", "/dev", "/boot", "/snap", "/var/lib/docker", "/var/lib/containers"}

// classify returns the destination a mount is, if it is one.
func classify(m mountInfo, labels map[string]string) (Destination, bool) {
	if m.MountPoint == "/" {
		return Destination{}, false
	}
	for _, s := range systemMounts {
		if m.MountPoint == s || strings.HasPrefix(m.MountPoint, s+"/") {
			return Destination{}, false
		}
	}
	if networkFS[m.FSType] {
		return Destination{Channel: policy.ChannelFileNetworkShare, Type: TypeNetworkShare, Mount: m.MountPoint,
			ShareHost: shareHost(m.FSType, m.Source), Source: m.Source}, true
	}
	if strings.HasPrefix(m.MajMin, "0:") {
		return Destination{}, false // not a block device (tmpfs, overlay, fuse, …)
	}
	removable, usb, dev := blockDevice(m.MajMin)
	if !removable {
		return Destination{}, false
	}
	return Destination{Channel: policy.ChannelFileRemovable, Type: TypeRemovable, Mount: m.MountPoint,
		VolumeLabel: labels[dev], USB: usb, Source: m.Source}, true
}

// shareHost takes the host out of a network mount's source: //host/share
// (SMB), host:/path (NFS), [user@]host:path (sshfs).
func shareHost(fstype, source string) string {
	if strings.HasPrefix(source, "//") {
		host, _, _ := strings.Cut(source[2:], "/")
		return host
	}
	rest := source
	if user, after, ok := strings.Cut(rest, "@"); ok && !strings.Contains(user, ":") {
		rest = after
	}
	if strings.HasPrefix(rest, "[") { // IPv6: [addr]:path
		if host, _, ok := strings.Cut(rest[1:], "]"); ok {
			return host
		}
		return ""
	}
	host, _, ok := strings.Cut(rest, ":")
	if !ok {
		return ""
	}
	return host
}

// blockDevice reports whether the block device majmin is removable: on a USB
// or MMC bus, or flagged removable. A device-mapper or md device (an
// encrypted USB stick) is followed to the devices under it. It also returns
// the USB ids and the kernel name of the device (for its label).
func blockDevice(majmin string) (bool, *events.USB, string) {
	return blockDeviceDepth(majmin, 0)
}

func blockDeviceDepth(majmin string, depth int) (bool, *events.USB, string) {
	if depth > 4 || !isMajMin(majmin) {
		return false, nil, ""
	}
	real, err := filepath.EvalSymlinks(filepath.Join(sysRoot, "dev", "block", majmin))
	if err != nil || !strings.HasPrefix(real, sysRoot+"/") {
		return false, nil, "" // sysfs links never leave /sys
	}
	name := filepath.Base(real)
	if strings.Contains(real, "/usb") {
		return true, usbIDs(real), name
	}
	if strings.Contains(real, "/mmc") {
		return true, nil, name
	}
	// A partition's removable flag is on its disk.
	for _, dir := range []string{real, filepath.Dir(real)} {
		if b, err := os.ReadFile(filepath.Join(dir, "removable")); err == nil && strings.TrimSpace(string(b)) == "1" { // #nosec G304 G703 -- under sysRoot (checked above)
			return true, nil, name
		}
	}
	slaves, _ := os.ReadDir(filepath.Join(real, "slaves"))
	for _, s := range slaves {
		dev, err := os.ReadFile(filepath.Join(real, "slaves", filepath.Base(s.Name()), "dev")) // #nosec G304 G703 -- under sysRoot (checked above)
		if err != nil {
			continue
		}
		if ok, usb, _ := blockDeviceDepth(strings.TrimSpace(string(dev)), depth+1); ok {
			return true, usb, name
		}
	}
	return false, nil, name
}

// isMajMin reports whether s is a device number, "major:minor".
func isMajMin(s string) bool {
	maj, minor, ok := strings.Cut(s, ":")
	if !ok || maj == "" || minor == "" {
		return false
	}
	for _, c := range maj + minor {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// usbIDs reads vendor, product and serial from the nearest USB device above
// a sysfs path.
func usbIDs(path string) *events.USB {
	for dir := path; strings.HasPrefix(dir, sysRoot+"/"); dir = filepath.Dir(dir) {
		vendor, err := os.ReadFile(filepath.Join(dir, "idVendor")) // #nosec G304 G703 -- under sysRoot (loop condition)
		if err != nil {
			continue
		}
		product, _ := os.ReadFile(filepath.Join(dir, "idProduct")) // #nosec G304 G703 -- under sysRoot (loop condition)
		serial, _ := os.ReadFile(filepath.Join(dir, "serial"))     // #nosec G304 G703 -- under sysRoot (loop condition)
		return &events.USB{VendorID: strings.TrimSpace(string(vendor)), ProductID: strings.TrimSpace(string(product)),
			Serial: strings.TrimSpace(string(serial))}
	}
	return nil
}

// volumeLabels maps kernel device names (sdb1) to filesystem labels, from the
// /dev/disk/by-label links udev maintains.
func volumeLabels() map[string]string {
	dir := filepath.Join(devRoot, "disk", "by-label")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	labels := map[string]string{}
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		labels[filepath.Base(target)] = unescapeUdev(e.Name())
	}
	return labels
}

// unescapeUdev decodes udev's \xNN escapes in link names.
func unescapeUdev(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && s[i+1] == 'x' {
			if v, err := strconv.ParseUint(s[i+2:i+4], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
