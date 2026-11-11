package filedlp

// WatchTree exposes the file DLP watcher (#330) to on-write threat hunting
// (#418): the same overlapped ReadDirectoryChangesW, on any folder.

// TreeWatch is a running WatchTree.
type TreeWatch struct{ w *dirWatch }

// Close ends the watch and waits for its loop. Safe to call more than once.
func (t *TreeWatch) Close() { t.w.close() }

// WatchTree watches root recursively and calls changed with the path of each
// file added, modified or renamed into place, lost when notifications were
// dropped (the buffer overflowed), and gone once if root goes away (the
// watch has then ended). The callbacks run on the watch's goroutine and
// must return quickly.
func WatchTree(root string, changed func(path string), lost func(), gone func()) (*TreeWatch, error) {
	w, err := startWatch(root,
		func(ch fsChange) {
			if ch.path != "" {
				changed(ch.path)
			}
		},
		func(string) { lost() },
		func(string) { gone() })
	if err != nil {
		return nil, err
	}
	return &TreeWatch{w: w}, nil
}
