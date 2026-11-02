package filedlp

import (
	"sync"
	"time"
)

// Process taint (#334, copy_correlation.process_taint): the hook remembers
// which files each process opened recently. When a process writes a file to
// a monitored destination that can't be judged on its own (unreadable, or an
// archive it built), the decider checks those source files instead. Nothing
// is scanned when a file is opened; only the path and identity are kept, in
// memory, for the taint window.

// SourceRef is a file a process opened.
type SourceRef struct {
	Path string
	Dev  uint64
	Ino  uint64
	At   time.Time
}

// Taint store bounds.
const (
	taintPerProcess = 32   // most recent opens kept per process
	taintMaxProcs   = 4096 // processes tracked
	taintMaxSources = 8    // sources checked for one written file
)

// taintStore is the recent opens per process. It is safe for concurrent use.
type taintStore struct {
	mu    sync.Mutex
	procs map[int]*procOpens
}

type procOpens struct {
	refs []SourceRef // oldest first, at most taintPerProcess
	last time.Time
}

func newTaintStore() *taintStore { return &taintStore{procs: map[int]*procOpens{}} }

// record notes that pid opened ref. A file opened again moves to the end.
func (t *taintStore) record(pid int, ref SourceRef) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.procs[pid]
	if p == nil {
		if len(t.procs) >= taintMaxProcs {
			t.evictOldestLocked()
		}
		p = &procOpens{}
		t.procs[pid] = p
	}
	for i, r := range p.refs {
		if r.Dev == ref.Dev && r.Ino == ref.Ino {
			p.refs = append(p.refs[:i], p.refs[i+1:]...)
			break
		}
	}
	p.refs = append(p.refs, ref)
	if len(p.refs) > taintPerProcess {
		p.refs = p.refs[len(p.refs)-taintPerProcess:]
	}
	p.last = ref.At
}

func (t *taintStore) evictOldestLocked() {
	oldest, at := -1, time.Time{}
	for pid, p := range t.procs {
		if oldest < 0 || p.last.Before(at) {
			oldest, at = pid, p.last
		}
	}
	delete(t.procs, oldest)
}

// sources returns what pid opened after since (its start, so a reused pid
// doesn't inherit another process's opens) and within window of now, newest
// first, at most taintMaxSources.
func (t *taintStore) sources(pid int, since, now time.Time, window time.Duration) []SourceRef {
	t.mu.Lock()
	defer t.mu.Unlock()
	p := t.procs[pid]
	if p == nil {
		return nil
	}
	var out []SourceRef
	for i := len(p.refs) - 1; i >= 0 && len(out) < taintMaxSources; i-- {
		r := p.refs[i]
		if r.At.Before(since) || now.Sub(r.At) > window {
			continue
		}
		out = append(out, r)
	}
	return out
}

// prune drops processes with nothing opened within window.
func (t *taintStore) prune(now time.Time, window time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for pid, p := range t.procs {
		if now.Sub(p.last) > window {
			delete(t.procs, pid)
		}
	}
}

// len is how many processes are tracked.
func (t *taintStore) len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.procs)
}
