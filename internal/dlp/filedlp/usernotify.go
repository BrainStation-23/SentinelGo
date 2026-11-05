package filedlp

// Telling the user why (#336): when a file is blocked, removed after the
// write, or matches a "warn" policy, the session helper of the user whose
// process did it shows a notification, so they don't think the machine is
// broken. The text names the file, the destination and the detectors, never
// the matched values. Copying a folder gives one notification, not one per
// file: notices are gathered per user, kind and destination for a short
// window, and a file retried within a minute (Explorer's "Try again", a sync
// client) isn't counted again. Every event says whether its user could be
// told (user_notified).

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"sentinelgo/internal/dlp/detect"
	"sentinelgo/internal/dlp/notify"
)

// UserNotifier reaches the session helper of one user's session (on Unix the
// session id is the uid).
type UserNotifier interface {
	SessionReadiness(sessionID string) (state string, ok bool)
	NotifySession(ctx context.Context, sessionID, title, body string) error
}

// Notice kinds.
const (
	noticeBlocked = "blocked"
	noticeRemoved = "removed"
	noticeWarned  = "warned"
)

// Notice timing; vars for tests.
var (
	noticeWindow = 3 * time.Second // gathered before one notification goes out
	noticeDedup  = time.Minute     // a file already told about isn't told again
)

const noticeSendTimeout = 20 * time.Second

type noticeKey struct{ uid, kind, dest string }

type noticeBatch struct {
	files     []string
	detectors map[string]bool
	message   string // the files module's block message, filled
}

type notices struct {
	n   UserNotifier
	now func() time.Time

	mu      sync.Mutex
	pending map[noticeKey]*noticeBatch
	seen    map[string]time.Time // uid|channel|sha256 → last told
	wg      sync.WaitGroup
}

func newNotices(n UserNotifier) *notices {
	return &notices{n: n, now: time.Now, pending: map[noticeKey]*noticeBatch{}, seen: map[string]time.Time{}}
}

// destLabel describes a destination for the user.
func destLabel(d Destination) string {
	switch {
	case d.Type == TypeRemovable && d.VolumeLabel != "":
		return fmt.Sprintf("the USB drive %q", d.VolumeLabel)
	case d.Type == TypeRemovable:
		return "a USB drive"
	case d.ShareHost != "":
		return "the network share on " + d.ShareHost
	case d.Host != "":
		return d.Host
	}
	return "a network share"
}

// report queues a notice for r's user and returns whether that user can be
// told: their session has a helper and notifications reach them.
func (s *notices) report(r Request, kind, sha string, findings []detect.Finding, v Verdict) bool {
	message := v.Message
	if s == nil || s.n == nil || r.Proc.UID == "" {
		return false
	}
	state, ok := s.n.SessionReadiness(r.Proc.UID)
	if !ok || !notify.Shows(state) {
		return false
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if sha != "" && s.retryLocked(r.Proc.UID+"|"+r.Dest.Channel+"|"+sha, now) {
		return true // told already; this is a retry
	}
	key := noticeKey{uid: r.Proc.UID, kind: kind, dest: destLabel(r.Dest)}
	b := s.pending[key]
	if b == nil {
		b = &noticeBatch{detectors: map[string]bool{}, message: message}
		s.pending[key] = b
		s.wg.Add(1)
		time.AfterFunc(noticeWindow, func() { s.flush(key) })
	}
	b.files = append(b.files, filepath.Base(r.Path))
	for _, f := range findings {
		b.detectors[f.DetectorID] = true
	}
	return true
}

// retryLocked reports whether this file was told about within noticeDedup,
// and records it.
func (s *notices) retryLocked(k string, now time.Time) bool {
	if t, ok := s.seen[k]; ok && now.Sub(t) < noticeDedup {
		return true
	}
	s.seen[k] = now
	if len(s.seen) > 4096 {
		for k, t := range s.seen {
			if now.Sub(t) >= noticeDedup {
				delete(s.seen, k)
			}
		}
	}
	return false
}

func (s *notices) flush(key noticeKey) {
	defer s.wg.Done()
	s.mu.Lock()
	b := s.pending[key]
	delete(s.pending, key)
	s.mu.Unlock()
	if b == nil {
		return
	}
	title, body := noticeText(key, b)
	ctx, cancel := context.WithTimeout(context.Background(), noticeSendTimeout)
	defer cancel()
	if err := s.n.NotifySession(ctx, key.uid, title, body); err != nil {
		// the error names the tool or the helper, never the text
		log.Printf("DLP: file %s notification not shown: %v", key.kind, err)
	}
}

// wait waits for queued notices (tests, shutdown).
func (s *notices) wait() {
	if s != nil {
		s.wg.Wait()
	}
}

func noticeText(key noticeKey, b *noticeBatch) (title, body string) {
	var ids []string
	for id := range b.detectors {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	what := strings.Join(ids, ", ")
	if what == "" {
		what = "content that couldn't be checked"
	}
	n := len(b.files)
	files := fmt.Sprintf("%q", b.files[0])
	if n > 1 {
		files = fmt.Sprintf("%d files", n)
	}
	switch key.kind {
	case noticeBlocked:
		title = "SentinelOps blocked a file"
		if n > 1 {
			title = fmt.Sprintf("SentinelOps blocked %d files", n)
		}
		body = fmt.Sprintf("%s (%s to %s). Ask IT if you need to share this.", b.message, files, key.dest)
	case noticeRemoved:
		title = "SentinelOps removed a file"
		if n > 1 {
			title = fmt.Sprintf("SentinelOps removed %d files", n)
		}
		body = fmt.Sprintf("%s copied to %s contain %s and were removed from it. Ask IT if you need to share this.", files, key.dest, what)
		if n == 1 {
			body = strings.NewReplacer(" contain ", " contains ", " were removed", " was removed").Replace(body)
		}
	default:
		title = "This file contains sensitive data"
		body = fmt.Sprintf("%s copied to %s contain %s. This was logged.", files, key.dest, what)
		if n == 1 {
			body = strings.Replace(body, " contain ", " contains ", 1)
		}
	}
	return title, body
}
