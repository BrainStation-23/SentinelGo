package filedlp

// Copy correlation at open time: a process that creates a file on a USB
// stick or a share usually has the file it copies from open at that moment
// (cp, rsync, a file manager), so the files it holds open for reading are
// the candidates for what is about to be written. Read from
// /proc/<pid>/fd and /proc/<pid>/fdinfo; no OS suffix, so tested on any host
// against a fixture.

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// copyPrograms are the processes whose open files tell what they are about
// to write: copy tools and file managers, which hold the source open while
// they create the copy. Other programs (editors, office suites, browsers)
// keep unrelated documents open, so a new file of theirs is never judged by
// them; the after-write path covers those. Matched on the executable's base
// name, or the process name (comm, 15 characters) when the exe is unknown.
var copyPrograms = map[string]bool{
	"cp": true, "mv": true, "rsync": true, "install": true, "dd": true, "tar": true,
	"nautilus": true, "nemo": true, "caja": true, "thunar": true, "pcmanfm": true, "pcmanfm-qt": true,
	"dolphin": true, "kioworker": true, "kioslave5": true, "konqueror": true, "krusader": true,
	"doublecmd": true, "mc": true, "spacefm": true, "xfe": true, "gvfsd": true, "gvfsd-smb": true,
	"gvfsd-sftp": true, "gvfsd-nfs": true, "gvfsd-afp": true,
}

// isCopyProgram reports whether a process is a copy tool or file manager.
func isCopyProgram(p Process) bool {
	if p.Exe != "" {
		return copyPrograms[filepath.Base(p.Exe)]
	}
	return copyPrograms[p.Name]
}

// maxOpenSources bounds the open files checked for one held open.
const maxOpenSources = 8

// systemPrefixes are never user data: libraries, caches, devices, our own
// install. A process's open files there (fonts, locale data) are skipped.
var systemPrefixes = []string{
	"/proc/", "/sys/", "/dev/", "/run/", "/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/",
	"/etc/", "/var/lib/", "/var/cache/", "/var/log/", "/snap/", "/opt/sentinelgo/",
}

// candidatePath reports whether an open file's path may be user data.
func candidatePath(p string) bool {
	if !strings.HasPrefix(p, "/") || strings.HasSuffix(p, " (deleted)") {
		return false // sockets, pipes, anon inodes, deleted files
	}
	for _, s := range systemPrefixes {
		if strings.HasPrefix(p, s) {
			return false
		}
	}
	return true
}

// fdReadable reports whether an fdinfo's flags allow reading (O_RDONLY or
// O_RDWR). flags is octal.
func fdReadable(fdinfo string) bool {
	for _, line := range strings.Split(fdinfo, "\n") {
		if v, ok := strings.CutPrefix(line, "flags:"); ok {
			f, err := strconv.ParseUint(strings.TrimSpace(v), 8, 64)
			if err != nil {
				return false
			}
			acc := f & 3
			return acc == 0 || acc == 2
		}
	}
	return false
}

// fileStat is a source's identity: dev, inode, size; ok false if it isn't a
// readable regular file. The Linux hook supplies it.
type fileStat func(path string) (dev, ino uint64, size int64, ok bool)

// openFileSources lists the regular files pid has open for reading, outside
// system paths and outside the destination being written (isDest), newest
// descriptor first, at most limit.
func openFileSources(root string, pid int, isDest func(string) bool, stat fileStat, limit int) []SourceRef {
	dir := filepath.Join(root, strconv.Itoa(pid))
	entries, err := os.ReadDir(filepath.Join(dir, "fd"))
	if err != nil {
		return nil
	}
	fds := make([]int, 0, len(entries))
	for _, e := range entries {
		if n, err := strconv.Atoi(e.Name()); err == nil && n > 2 {
			fds = append(fds, n)
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(fds)))
	var out []SourceRef
	seen := map[[2]uint64]bool{}
	for _, fd := range fds {
		if len(out) >= limit {
			break
		}
		name := strconv.Itoa(fd)
		target, err := os.Readlink(filepath.Join(dir, "fd", name))
		if err != nil || !candidatePath(target) || isDest(target) {
			continue
		}
		info, err := os.ReadFile(filepath.Join(dir, "fdinfo", name)) // #nosec G304 -- procfs
		if err != nil || !fdReadable(string(info)) {
			continue
		}
		dev, ino, size, ok := stat(target)
		if !ok || size <= 0 || seen[[2]uint64{dev, ino}] {
			continue
		}
		seen[[2]uint64{dev, ino}] = true
		out = append(out, SourceRef{Path: target, Dev: dev, Ino: ino})
	}
	return out
}
