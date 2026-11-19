package mdmenroll

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"time"

	"sentinelgo/internal/dlp/ipc"
)

// The Enroll now offer (#545). Once the console asked for a profile
// enrollment, a Mac that still isn't enrolled offers its user, from time to
// time and only while they are at the Mac, a dialog with Enroll now. That
// presents a new profile on the spot, so a user who missed or dismissed the
// first one can always get it back. A notification can't carry the button:
// macOS gives actionable notifications only to app bundles, and the agent is
// a single binary.
var (
	// offerEvery is the least time between two offers to one user, and
	// between a presentation and the next offer.
	offerEvery = 4 * time.Hour
	// offerCheck is how often the loop looks at the Mac.
	offerCheck = 5 * time.Minute
	// offerWait bounds how long the service waits for the user's choice;
	// the helper closes the dialog sooner.
	offerWait = 11 * time.Minute
	// offerForget drops users not shown anything for this long from the
	// state.
	offerForget = 30 * 24 * time.Hour
)

const (
	offerTitle   = "Enroll this Mac in device management"
	offerMessage = "Your organization needs this Mac enrolled in its device management. Enroll now opens System Settings with the enrollment profile; installing it takes a minute and your Mac password."
)

// offerState is what the offer keeps, in Deps.OfferState when set.
type offerState struct {
	// ArmedAt is when a task presented, or tried to present, a profile;
	// zero means no offers.
	ArmedAt time.Time `json:"armed_at,omitzero"`
	// Shown is, per user, when they were last shown a profile or an offer.
	Shown map[string]time.Time `json:"shown,omitempty"`
}

// state returns the offer's state, loading it on first use. Callers hold
// e.mu.
func (e *Enroller) state() *offerState {
	if e.offer != nil {
		return e.offer
	}
	e.offer = &offerState{}
	if e.d.OfferState != "" {
		if b, err := os.ReadFile(e.d.OfferState); err == nil {
			if json.Unmarshal(b, e.offer) != nil {
				*e.offer = offerState{}
			}
		}
	}
	if e.offer.Shown == nil {
		e.offer.Shown = map[string]time.Time{}
	}
	return e.offer
}

// save writes the state. Callers hold e.mu. A failure only costs the state
// across a restart.
func (e *Enroller) save() {
	if e.d.OfferState == "" {
		return
	}
	now := e.d.Now()
	for u, t := range e.offer.Shown {
		if now.Sub(t) > offerForget {
			delete(e.offer.Shown, u)
		}
	}
	b, err := json.Marshal(e.offer)
	if err != nil {
		return
	}
	tmp := e.d.OfferState + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		log.Printf("mdm-enroll: saving the Enroll now state: %v", err)
		return
	}
	if err := os.Rename(tmp, e.d.OfferState); err != nil {
		_ = os.Remove(tmp)
		log.Printf("mdm-enroll: saving the Enroll now state: %v", err)
	}
}

// arm starts the offers: the console asked for a profile enrollment.
func (e *Enroller) arm() {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.state()
	if st.ArmedAt.IsZero() {
		st.ArmedAt = e.d.Now()
		e.save()
	}
}

// disarm stops the offers: the Mac is enrolled.
func (e *Enroller) disarm() {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.state()
	if !st.ArmedAt.IsZero() || len(st.Shown) > 0 {
		*st = offerState{Shown: map[string]time.Time{}}
		e.save()
	}
}

// shown records that user was just shown a profile or an offer.
func (e *Enroller) shown(user string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.state().Shown[user] = e.d.Now()
	e.save()
}

// offerDue says whether offers are on and user wasn't shown anything for
// offerEvery.
func (e *Enroller) offerDue(user string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := e.state()
	last, ok := st.Shown[user]
	return !st.ArmedAt.IsZero() && (!ok || e.d.Now().Sub(last) >= offerEvery)
}

// RunOffers offers Enroll now (offerOnce) every offerCheck until ctx ends.
func (e *Enroller) RunOffers(ctx context.Context) {
	if e.d.Offer == nil || e.d.ConsoleSession == nil {
		return
	}
	t := time.NewTicker(offerCheck)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.offerOnce(ctx)
		}
	}
}

// offerOnce offers Enroll now to the console user when offers are on, the
// Mac isn't enrolled, the user is at the Mac and wasn't shown anything for
// offerEvery; on Enroll now it presents a new profile.
func (e *Enroller) offerOnce(ctx context.Context) {
	sess, ok := e.d.ConsoleSession()
	if !ok || !e.offerDue(sess.User) {
		return
	}
	host := ""
	if e.d.OurHost != nil {
		host = e.d.OurHost()
	}
	info := e.d.Collect(host)
	switch {
	case info == nil || info.Eligible != nil:
		return // not a Mac
	case info.Enrolled:
		e.disarm() // ours, or another MDM's, which the agent never touches
		return
	case info.ADEAssigned != nil && *info.ADEAssigned:
		return // ADE prompts by itself
	}
	if e.d.UserActive != nil && !e.d.UserActive(sess) {
		return
	}
	e.shown(sess.User)

	octx, cancel := context.WithTimeout(ctx, offerWait)
	yes, err := e.d.Offer(octx, sess.ID, ipc.OfferEnroll{Title: offerTitle, Message: offerMessage})
	cancel()
	if err != nil {
		log.Printf("mdm-enroll: Enroll now not offered to %s: %v", sess.User, err)
		return
	}
	if !yes {
		return
	}
	out, err := e.present(ctx, sess)
	if err != nil {
		log.Printf("mdm-enroll: %s chose Enroll now, but the profile wasn't presented: %v", sess.User, err)
		return
	}
	log.Printf("mdm-enroll: %s chose Enroll now: %s", sess.User, out)
}

// OfferStatePath is the offer's state file in the agent's config dir.
func OfferStatePath(configPath string) string {
	return filepath.Join(filepath.Dir(configPath), "mdm_enroll_offer.json")
}
