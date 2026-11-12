//go:build windows || darwin

package watch

import "sentinelgo/internal/dlp/filedlp"

// trees is one file DLP tree watch per root (ReadDirectoryChangesW on
// Windows, an FSEvents stream on macOS).
type trees []*filedlp.TreeWatch

func (t trees) Close() {
	for _, w := range t {
		w.Close()
	}
}

func start(roots []string, h Handler) (Watcher, error) {
	var out trees
	fail := failures{total: len(roots)}
	for _, root := range roots {
		w, err := filedlp.WatchTree(root, h.Changed, h.Lost, func() { h.Gone(root) })
		if err != nil {
			fail.add(err)
			continue
		}
		out = append(out, w)
	}
	if len(out) == 0 {
		return nil, fail.err()
	}
	return out, fail.err()
}
