package filedlp

// Asking the user (#336 part 2): a file blocked by a block_override policy
// opens a dialog in its user's session (prompt.Show, through the helper):
// go ahead with a reason, ask IT for an exception, or leave it. It happens
// after the block, never while an OS hook waits. One dialog per user at a
// time; further blocks meanwhile get the usual notification.

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"time"

	"sentinelgo/internal/dlp/detect"
	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/notify"
)

// Choices the dialog returns (prompt.Choice*).
const (
	choiceOverride = "override"
	choiceRequest  = "request"
)

// askTimeout bounds a dialog (the helper also gives up after 10 minutes).
const askTimeout = 11 * time.Minute

// ExceptionRequest is what agent_request_dlp_exception takes
// (Compliance-OS#581). FileName follows the evidence mode, like events.
type ExceptionRequest struct {
	PolicyID      string
	Channel       string
	EventID       string
	User          string
	SHA256        string
	FileName      *string
	Justification string
}

// Asker shows the block_override dialog in one user's session.
type Asker interface {
	AskOverride(ctx context.Context, sessionID, title, message string, canOverride, canRequest bool) (choice, reason string, err error)
}

// asking tracks the users with a dialog open.
type asking struct {
	mu    sync.Mutex
	users map[string]bool
	wg    sync.WaitGroup
}

func (a *asking) start(uid string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.users == nil {
		a.users = map[string]bool{}
	}
	if a.users[uid] {
		return false
	}
	a.users[uid] = true
	a.wg.Add(1)
	return true
}

func (a *asking) done(uid string) {
	a.mu.Lock()
	delete(a.users, uid)
	a.mu.Unlock()
	a.wg.Done()
}

// SetExceptionRequester sends exception requests to the backend; nil means
// the dialog doesn't offer one.
func (d *Decider) SetExceptionRequester(f func(context.Context, ExceptionRequest) error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.requestException = f
}

// ask opens the dialog for an overridable block and returns whether the
// user could be asked. ok=false: fall back to a notification.
func (d *Decider) ask(ev events.Event, r Request, v Verdict, sha string, limit int) bool {
	d.mu.Lock()
	n, request := d.notices, d.requestException
	d.mu.Unlock()
	if n == nil || r.Proc.UID == "" {
		return false
	}
	asker, ok := n.n.(Asker)
	if !ok {
		return false
	}
	state, ok := n.n.SessionReadiness(r.Proc.UID)
	if !ok || !notify.Shows(state) {
		return false
	}
	canOverride := d.overrides.remaining(r.Proc.UID, limit) > 0
	canRequest := request != nil
	if (!canOverride && !canRequest) || !d.asking.start(r.Proc.UID) {
		return false
	}
	name := filepath.Base(r.Path)
	msg := fmt.Sprintf("%s (%q to %s).", v.Message, name, destLabel(r.Dest))
	go func() {
		defer d.asking.done(r.Proc.UID)
		ctx, cancel := context.WithTimeout(context.Background(), askTimeout)
		defer cancel()
		choice, reason, err := asker.AskOverride(ctx, r.Proc.UID, "SentinelOps blocked a file", msg, canOverride, canRequest)
		if err != nil {
			log.Printf("DLP: block_override dialog not shown: %v", err)
			return
		}
		result := d.answer(ctx, ev, r.Proc.UID, name, sha, choice, reason, request)
		if result == "" {
			return
		}
		nctx, ncancel := context.WithTimeout(context.Background(), noticeSendTimeout)
		defer ncancel()
		if err := n.n.NotifySession(nctx, r.Proc.UID, "SentinelOps", result); err != nil {
			log.Printf("DLP: override result not shown: %v", err)
		}
	}()
	return true
}

// answer acts on the user's choice and returns what to tell them ("" for
// cancel).
func (d *Decider) answer(ctx context.Context, ev events.Event, uid, name, sha, choice, reason string,
	request func(context.Context, ExceptionRequest) error) string {
	switch choice {
	case choiceOverride:
		if err := d.Override(ev.EventID, uid, reason); err != nil {
			return "Not allowed: " + err.Error() + "."
		}
		return fmt.Sprintf("You can copy %q now. It is allowed for %d minutes, and your reason was recorded.", name, int(overrideAllowFor/time.Minute))
	case choiceRequest:
		req := ExceptionRequest{PolicyID: ev.PolicyID, Channel: ev.Channel, EventID: ev.EventID, User: ev.User,
			SHA256: sha, Justification: reason}
		if ev.File != nil {
			req.FileName = ev.File.Name
		}
		if err := request(ctx, req); err != nil {
			log.Printf("DLP: exception request not sent: %v", err)
			return "Your request couldn't be sent. Try again later, or contact IT."
		}
		return "Your request was sent to IT. You'll be able to copy the file once it is approved."
	}
	return ""
}

// tellBlock asks about an overridable block, else queues a notification.
func (d *Decider) tellBlock(ev *events.Event, r Request, v Verdict, sha string, limit int, findings []detect.Finding) {
	if v.Overridable && d.ask(*ev, r, v, sha, limit) {
		told := true
		ev.UserNotified = &told
		return
	}
	d.tell(ev, r, noticeBlocked, v, findings)
}
