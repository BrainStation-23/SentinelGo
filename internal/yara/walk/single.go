package walk

// One file at a time, for on-write scanning (#418): the folders watched and
// the same per-file checks a walk makes, for a path a file system
// notification named.

import (
	"io/fs"

	"sentinelgo/internal/yara"
)

// OnWriteRoots returns the folders on-write scanning watches: the bundle's
// on_write paths for this OS, or, when there are none, the on-write
// defaults. Like Roots, it expands variables and "*", drops folders that
// don't exist and merges nested ones.
func OnWriteRoots(paths []string, env Env) []string {
	if len(paths) == 0 {
		paths = onWritePaths(env)
	}
	return Roots(yara.PresetCustom, paths, env)
}

// onWritePaths are the on-write defaults (contract v1.1): the quick
// preset's folders without the ones that change all the time
// (%ProgramData%, /private/var/folders, /root), where scanning every write
// would cost more than it finds.
func onWritePaths(env Env) []string {
	var out []string
	in := func(home, rel string) string { return clean(home+separator(env.GOOS)+rel, env.GOOS) }
	switch env.GOOS {
	case "windows":
		for _, h := range env.Homes {
			out = append(out,
				in(h, "Downloads"),
				in(h, "Desktop"),
				in(h, `AppData\Local\Temp`),
				in(h, `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`))
		}
		out = append(out, `%PUBLIC%`, `%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp`, `%SystemRoot%\Temp`)
	case "darwin":
		for _, h := range env.Homes {
			out = append(out,
				in(h, "Downloads"),
				in(h, "Desktop"),
				in(h, "Library/LaunchAgents"))
		}
		out = append(out, "/private/tmp", "/Library/LaunchAgents", "/Library/LaunchDaemons")
	case "linux":
		for _, h := range env.Homes {
			out = append(out,
				in(h, "Downloads"),
				in(h, ".config/autostart"))
		}
		out = append(out, "/tmp", "/var/tmp", "/dev/shm", "/etc/systemd/system", "/etc/cron*")
	}
	return out
}

// Under returns the root of roots that contains p, if any.
func Under(p string, roots []string, goos string) (string, bool) {
	for _, r := range roots {
		if within(p, r, goos) {
			return r, true
		}
	}
	return "", false
}

// Excluded reports whether o's exclusions, or its network and removable
// drive limits, leave p out. It doesn't touch the file system.
func Excluded(o Options, p string) bool { return excludedReason(o, p) != "" }

func excludedReason(o Options, p string) string {
	if o.Exclude.Excluded(p, baseName(p, o.GOOS)) {
		return SkipExcluded
	}
	w := &walker{o: o, mounts: make(map[string]Mount, len(o.Mounts))}
	for _, m := range o.Mounts {
		w.mounts[w.fold(m.Path)] = m
	}
	if reason, skip := w.mountSkip(p, true); skip {
		return reason
	}
	return ""
}

// Stat applies a walk's per-file checks to the single file p: it must not
// be excluded (Excluded), must be a regular file and not a link, must have
// its content on the device, must fit o.MaxFileBytes and, with o.Cache,
// must have changed since its last scan with o.Rules. It returns the File
// to scan, or the skip reason (one of the Skip* constants) and no error. A
// file that is gone returns fs.ErrNotExist.
func Stat(o Options, p string) (File, string, error) {
	if reason := excludedReason(o, p); reason != "" {
		return File{}, reason, nil
	}
	info, err := lstat(p)
	if err != nil {
		return File{}, "", err
	}
	switch {
	case info.Mode()&(fs.ModeSymlink|fs.ModeIrregular) != 0:
		return File{}, SkipLink, nil
	case !info.Mode().IsRegular():
		return File{}, SkipSpecial, nil
	case placeholder(info):
		return File{}, SkipCloud, nil
	case o.MaxFileBytes > 0 && info.Size() > o.MaxFileBytes:
		return File{}, SkipTooLarge, nil
	}
	f := File{Path: p, Size: info.Size(), Key: keyOf(p, info), id: idOf(info)}
	if o.Cache != nil {
		if _, ok := o.Cache.Lookup(f.Key, o.Rules); ok {
			return File{}, SkipUnchanged, nil
		}
	}
	return f, "", nil
}
