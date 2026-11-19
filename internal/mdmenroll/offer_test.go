package mdmenroll

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"sentinelgo/internal/dlp/ipc"
)

// offerDevice is a fakeDevice whose user answers the Enroll now dialog.
type offerDevice struct {
	*fakeDevice
	offers []ipc.OfferEnroll
	answer bool
	err    error
	// during runs while the dialog is open.
	during func()
}

func newOfferDevice() *offerDevice {
	return &offerDevice{fakeDevice: &fakeDevice{
		info:    notEnrolled(nil, ""),
		console: &Session{ID: "501", User: "alice"},
		clock:   time.Unix(1_800_000_000, 0),
	}}
}

func (o *offerDevice) deps(state string) Deps {
	d := o.fakeDevice.deps()
	d.OfferState = state
	d.Offer = func(_ context.Context, sid string, x ipc.OfferEnroll) (bool, error) {
		if sid != o.console.ID {
			return false, errors.New("wrong session " + sid)
		}
		o.offers = append(o.offers, x)
		if o.during != nil {
			o.during()
		}
		return o.answer, o.err
	}
	return d
}

// No offers until the console asked for a profile enrollment.
func TestOffer_OnlyAfterATask(t *testing.T) {
	o := newOfferDevice()
	e := New(o.deps(""))
	e.offerOnce(context.Background())
	if len(o.offers) != 0 {
		t.Fatalf("offered %d times without a task", len(o.offers))
	}

	// The task's user was idle the whole time: they're offered it later.
	o.active = func() bool { return false }
	if _, err := e.Enroll(context.Background(), Request{Method: MethodProfile}); outcomeCode(t, err) != ResultUserIdleTimeout {
		t.Fatalf("err = %v", err)
	}
	e.offerOnce(context.Background())
	if len(o.offers) != 0 {
		t.Error("offered to an idle user")
	}
	o.active = nil
	e.offerOnce(context.Background())
	if len(o.offers) != 1 || o.offers[0].Title == "" || o.offers[0].Message == "" {
		t.Fatalf("offers = %+v", o.offers)
	}
	if o.fetches != 0 {
		t.Error("presented a profile though the user chose Later")
	}
}

// Enroll now presents a new profile right away; offers come at most every
// offerEvery, counted from the last thing shown.
func TestOffer_EnrollNowAndCadence(t *testing.T) {
	o := newOfferDevice()
	e := New(o.deps(""))
	if _, err := e.Enroll(context.Background(), Request{Method: MethodProfile}); err != nil {
		t.Fatal(err)
	}
	o.clock = o.clock.Add(time.Hour)
	e.offerOnce(context.Background())
	if len(o.offers) != 0 {
		t.Fatal("offered an hour after the profile was presented")
	}

	o.clock = o.clock.Add(offerEvery)
	o.answer = true
	e.offerOnce(context.Background())
	if len(o.offers) != 1 || o.fetches != 2 || len(o.presented) != 2 {
		t.Fatalf("offers %d fetches %d presented %d", len(o.offers), o.fetches, len(o.presented))
	}
	e.offerOnce(context.Background())
	if len(o.offers) != 1 {
		t.Error("offered again right after Enroll now")
	}

	// A dialog that wasn't shown (no helper, osascript failed) presents
	// nothing and is tried again at the next check, not hours later.
	o.clock = o.clock.Add(offerEvery)
	o.err = errors.New("no helper")
	e.offerOnce(context.Background())
	o.clock = o.clock.Add(offerCheck)
	o.err = nil
	e.offerOnce(context.Background())
	if len(o.offers) != 3 || o.fetches != 3 {
		t.Errorf("offers %d fetches %d", len(o.offers), o.fetches)
	}
}

// No offer while a profile task waits for the user or for the enrollment;
// and Enroll now doesn't supersede a profile presented while its dialog was
// open, or present one to a Mac that enrolled meanwhile.
func TestOffer_DoesntSupersedeATask(t *testing.T) {
	o := newOfferDevice()
	e := New(o.deps(""))
	e.arm()
	e.taskBusy(1)
	e.offerOnce(context.Background())
	if len(o.offers) != 0 {
		t.Fatal("offered while a task was in flight")
	}
	e.taskBusy(-1)

	o.answer = true
	o.during = func() {
		if _, err := e.present(context.Background(), *o.console); err != nil {
			t.Error(err)
		}
	}
	e.offerOnce(context.Background())
	if len(o.offers) != 1 || o.fetches != 1 {
		t.Errorf("offers %d fetches %d: the task's profile was superseded", len(o.offers), o.fetches)
	}

	o.clock = o.clock.Add(offerEvery)
	o.during = func() { o.info = enrolledOurs }
	e.offerOnce(context.Background())
	if len(o.offers) != 2 || o.fetches != 1 {
		t.Errorf("offers %d fetches %d: presented to an enrolled Mac", len(o.offers), o.fetches)
	}
}

// Once the Mac is enrolled, in our MDM or another, the offers stop for good.
func TestOffer_StopsWhenEnrolled(t *testing.T) {
	o := newOfferDevice()
	e := New(o.deps(""))
	e.arm()
	o.info = enrolledOurs
	e.offerOnce(context.Background())
	o.info = notEnrolled(nil, "")
	o.clock = o.clock.Add(offerEvery)
	e.offerOnce(context.Background())
	if len(o.offers) != 0 {
		t.Errorf("offered %d times after the Mac enrolled", len(o.offers))
	}

	// A task that sees the Mac enrolled stops them too.
	e.arm()
	o.info = enrolledOurs
	if _, err := e.Enroll(context.Background(), Request{}); err != nil {
		t.Fatal(err)
	}
	o.info = notEnrolled(nil, "")
	e.offerOnce(context.Background())
	if len(o.offers) != 0 {
		t.Error("offered after a task found the Mac enrolled")
	}
}

// Not on Windows (eligibility reported) or an ADE Mac, which prompts itself.
func TestOffer_NotForWindowsOrADE(t *testing.T) {
	yes := true
	for name, info := range map[string]any{
		"windows": &yes,
		"ade":     ptr(true),
	} {
		o := newOfferDevice()
		if name == "windows" {
			o.info.Eligible = info.(*bool)
		} else {
			o.info.ADEAssigned = info.(*bool)
		}
		e := New(o.deps(""))
		e.arm()
		e.offerOnce(context.Background())
		if len(o.offers) != 0 {
			t.Errorf("%s: offered", name)
		}
	}
}

// The offers survive a restart: armed, and when each user was last shown.
func TestOffer_StatePersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mdm_enroll_offer.json")
	o := newOfferDevice()
	e := New(o.deps(path))
	if _, err := e.Enroll(context.Background(), Request{Method: MethodProfile}); err != nil {
		t.Fatal(err)
	}

	// Restarted an hour later: armed, and alice was shown a profile.
	o.clock = o.clock.Add(time.Hour)
	e = New(o.deps(path))
	e.offerOnce(context.Background())
	if len(o.offers) != 0 {
		t.Fatal("offered right after a restart; the last presentation was forgotten")
	}
	o.clock = o.clock.Add(offerEvery)
	e.offerOnce(context.Background())
	if len(o.offers) != 1 {
		t.Fatalf("not offered after a restart: %d", len(o.offers))
	}

	// Enrolled by the next check: disarmed on disk too.
	o.info = enrolledOurs
	o.clock = o.clock.Add(offerEvery)
	e.offerOnce(context.Background())
	o.info = notEnrolled(nil, "")
	o.clock = o.clock.Add(offerEvery)
	New(o.deps(path)).offerOnce(context.Background())
	if len(o.offers) != 1 {
		t.Error("offered after a restart though the Mac had enrolled")
	}
}

func TestOffer_RunOffersStops(t *testing.T) {
	o := newOfferDevice()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { New(o.deps("")).RunOffers(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunOffers didn't stop")
	}
	// Without Offer it returns at once.
	d := o.deps("")
	d.Offer = nil
	New(d).RunOffers(context.Background())
}
