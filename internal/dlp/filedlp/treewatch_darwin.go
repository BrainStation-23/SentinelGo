package filedlp

// WatchTree exposes the file DLP FSEvents stream (#332) to on-write threat
// hunting (#418): file-level events for any folder, through purego (no
// cgo), ignoring the agent's own writes.

// TreeWatch is a running WatchTree.
type TreeWatch struct{ s *fseStream }

// Close stops the stream; no callback runs after it returns. Safe to call
// more than once.
func (t *TreeWatch) Close() { t.s.close() }

// WatchTree watches root recursively and calls changed with the path of each
// file created, modified or renamed into place by another process, lost
// when events were dropped, and gone if root was unmounted or moved. The
// callbacks run on the FSEvents dispatch queue and must return quickly.
func WatchTree(root string, changed func(path string), lost func(), gone func()) (*TreeWatch, error) {
	s, err := startFSEvents(root,
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
	return &TreeWatch{s: s}, nil
}
