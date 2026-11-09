//go:build windows || darwin

package filedlp

// Waiting for a writer to finish, for hooks that only learn that a name
// changed (Windows ReadDirectoryChangesW, macOS FSEvents): a changed file is
// kept here until it has been quiet for a while, then opened for its
// decision; a file still being written is looked at again later.

import (
	"io/fs"
	"path/filepath"
	"sync/atomic"
	"time"
)

// Tuning; vars for tests.
var (
	quietFor      = time.Second     // a file must be unchanged this long before it is scanned
	tempQuietFor  = 5 * time.Second // longer for temp names: a save usually renames them first
	pendingTick   = 250 * time.Millisecond
	pendingGiveUp = 10 * time.Minute // a file still being written after this is dropped
	rescanWindow  = 5 * time.Minute  // after lost events, files changed this recently are scanned
)

const (
	maxPending      = 4096
	changeQueueSize = 4096
	maxRescanFiles  = 5000
)

// fsChange is one changed file under a watched root; path "" asks for a
// rescan of the root (events were lost).
type fsChange struct {
	root string
	path string
}

type openStatus int

const (
	openOK    openStatus = iota
	openRetry            // still being written: look again later
	openSkip             // gone, not a regular file, or not ours
)

type pendingFile struct {
	first, last time.Time
}

// pendingSet is the changed files waiting; owned by one goroutine.
type pendingSet struct {
	m                   map[string]*pendingFile
	dropped, unreadable *atomic.Uint64
}

func newPendingSet(dropped, unreadable *atomic.Uint64) *pendingSet {
	return &pendingSet{m: map[string]*pendingFile{}, dropped: dropped, unreadable: unreadable}
}

// add notes that path changed at now (a rescan request adds every recently
// changed file under its root).
func (p *pendingSet) add(ch fsChange, now time.Time) {
	if ch.path == "" {
		for _, f := range rescan(ch.root, now.Add(-rescanWindow)) {
			p.addPath(f, now)
		}
		return
	}
	p.addPath(ch.path, now)
}

func (p *pendingSet) addPath(path string, now time.Time) {
	if f, ok := p.m[path]; ok {
		f.last = now
		return
	}
	if len(p.m) >= maxPending {
		p.dropped.Add(1)
		return
	}
	p.m[path] = &pendingFile{first: now, last: now}
}

// due opens each file that has been quiet long enough and queues it.
func (p *pendingSet) due(now time.Time, open func(path string, now time.Time) (Request, openStatus), queue chan<- Request) {
	for path, f := range p.m {
		quiet := quietFor
		if isTempName(filepath.Base(path)) {
			quiet = tempQuietFor
		}
		if now.Sub(f.last) < quiet {
			continue
		}
		r, st := open(path, now)
		switch st {
		case openRetry:
			if now.Sub(f.first) > pendingGiveUp {
				delete(p.m, path)
				p.unreadable.Add(1)
			} else {
				f.last = now // look again after another quiet period
			}
		case openSkip:
			delete(p.m, path)
		case openOK:
			delete(p.m, path)
			select {
			case queue <- r:
			default:
				_ = r.File.Close()
				p.dropped.Add(1)
			}
		}
	}
}

// rescan lists the files under root changed since since, at most
// maxRescanFiles.
func rescan(root string, since time.Time) []string {
	var out []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // skip what can't be read
		}
		if len(out) >= maxRescanFiles {
			return filepath.SkipAll
		}
		if d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil && fi.ModTime().After(since) {
				out = append(out, path)
			}
		}
		return nil
	})
	return out
}
