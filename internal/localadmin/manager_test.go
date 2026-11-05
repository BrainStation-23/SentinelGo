package localadmin

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeGroup records adds and removes; members is the admin set.
type fakeGroup struct {
	members   map[string]bool
	removeErr error
	adds      int
	removes   int
}

func (g *fakeGroup) IsMember(_ context.Context, r Request) (bool, error) {
	return g.members[r.Member], nil
}
func (g *fakeGroup) Add(_ context.Context, r Request) (Outcome, error) {
	g.adds++
	if g.members[r.Member] {
		return Outcome{Success: true, State: StateAlready, Member: r.Member}, nil
	}
	g.members[r.Member] = true
	return Outcome{Success: true, State: StateAdded, Member: r.Member}, nil
}
func (g *fakeGroup) Remove(_ context.Context, r Request) (Outcome, error) {
	g.removes++
	if g.removeErr != nil {
		return Outcome{}, g.removeErr
	}
	if !g.members[r.Member] {
		return Outcome{Success: true, State: StateAbsent, Member: r.Member}, nil
	}
	delete(g.members, r.Member)
	return Outcome{Success: true, State: StateRemoved, Member: r.Member}, nil
}

type fakeBackup struct {
	scheduled map[string]time.Time
	cancelled []string
	err       error
}

func (b *fakeBackup) Schedule(_ context.Context, id string, at time.Time) error {
	if b.err != nil {
		return b.err
	}
	b.scheduled[id] = at
	return nil
}
func (b *fakeBackup) Cancel(_ context.Context, id string) error {
	b.cancelled = append(b.cancelled, id)
	delete(b.scheduled, id)
	return nil
}

type clock struct {
	wall time.Time
	mono time.Duration // what since() returns
}

func testManager(t *testing.T) (*Manager, *fakeGroup, *fakeBackup, *clock) {
	t.Helper()
	g := &fakeGroup{members: map[string]bool{"it": true}}
	b := &fakeBackup{scheduled: map[string]time.Time{}}
	c := &clock{wall: time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)}
	m := NewManager(filepath.Join(t.TempDir(), StoreFile), g, b)
	m.now = func() time.Time { return c.wall }
	m.since = func(time.Time) time.Duration { return c.mono }
	return m, g, b, c
}

func grantReq(member, id string, exp time.Time) Request {
	return Request{Member: member, GrantID: id, ExpiresAt: &exp}
}

func TestManager_GrantAndExpire(t *testing.T) {
	m, g, b, c := testManager(t)
	ctx := context.Background()
	exp := c.wall.Add(2 * time.Hour)
	out, err := m.Apply(ctx, true, grantReq("alice", "g1", exp))
	if err != nil || out.State != StateAdded || !g.members["alice"] || !b.scheduled["g1"].Equal(exp) {
		t.Fatalf("%+v %v %v", out, err, b.scheduled)
	}
	rep := Report(m.path, c.wall)
	if len(rep) != 1 || rep[0].State != GrantActive {
		t.Fatalf("report %+v", rep)
	}
	m.Check(ctx)
	if !g.members["alice"] {
		t.Fatal("removed early")
	}
	c.wall = exp.Add(time.Second)
	m.Check(ctx)
	if g.members["alice"] {
		t.Fatal("not removed at expiry")
	}
	rep = Report(m.path, c.wall)
	if len(rep) != 1 || rep[0].State != GrantRemoved || rep[0].RemovedAt == nil || len(b.cancelled) != 1 {
		t.Fatalf("after: %+v %v", rep, b.cancelled)
	}
	// kept 7 days, then dropped
	c.wall = c.wall.Add(8 * 24 * time.Hour)
	if r := Report(m.path, c.wall); len(r) != 0 {
		t.Fatalf("not pruned in report: %+v", r)
	}
	m.Check(ctx)
	if d, _ := m.load(); len(d.Grants) != 0 {
		t.Fatalf("not pruned in store: %+v", d.Grants)
	}
}

// A deadline missed while the agent was down is handled by the first check
// of a new manager (a restart).
func TestManager_MissedDeadlineAtStart(t *testing.T) {
	m, g, _, c := testManager(t)
	ctx := context.Background()
	if _, err := m.Apply(ctx, true, grantReq("alice", "g1", c.wall.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	m2 := NewManager(m.path, g, &fakeBackup{scheduled: map[string]time.Time{}})
	m2.now = func() time.Time { return c.wall.Add(3 * 24 * time.Hour) }
	ctx2, cancel := context.WithCancel(ctx)
	cancel() // Run checks once, then returns
	m2.Run(ctx2, time.Hour)
	if g.members["alice"] {
		t.Fatal("missed deadline not enforced at start")
	}
}

func TestManager_ClockSetBack(t *testing.T) {
	m, g, _, c := testManager(t)
	ctx := context.Background()
	exp := c.wall.Add(2 * time.Hour)
	if _, err := m.Apply(ctx, true, grantReq("alice", "g1", exp)); err != nil {
		t.Fatal(err)
	}
	// the high-water mark follows the clock
	c.wall = c.wall.Add(90 * time.Minute)
	m.Check(ctx)

	// monotonic: the process has run past the end although the wall clock
	// was set back to just after the grant started
	c.wall = c.wall.Add(-89 * time.Minute)
	c.mono = 3 * time.Hour
	m.Check(ctx)
	if g.members["alice"] {
		t.Fatal("clock set back extended the grant (monotonic)")
	}

	// high-water: after a restart (no monotonic mark), a clock set back
	// below the mark still counts from the mark
	m2, g2, _, c2 := testManager(t)
	if _, err := m2.Apply(ctx, true, grantReq("bob", "g2", c2.wall.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	c2.wall = c2.wall.Add(61 * time.Minute)
	if d, _ := m2.load(); true {
		d.HighWater = c2.wall
		if err := m2.save(d); err != nil {
			t.Fatal(err)
		}
	}
	m3 := NewManager(m2.path, g2, &fakeBackup{scheduled: map[string]time.Time{}})
	m3.now = func() time.Time { return c2.wall.Add(-30 * time.Minute) }
	m3.since = func(time.Time) time.Duration { return 0 }
	m3.Check(ctx)
	if g2.members["bob"] {
		t.Fatal("clock set back extended the grant (high-water)")
	}
}

// A wall clock earlier than the grant's start: on doubt, remove.
func TestManager_ClockBeforeGrantRemoves(t *testing.T) {
	m, g, _, c := testManager(t)
	ctx := context.Background()
	if _, err := m.Apply(ctx, true, grantReq("alice", "g1", c.wall.Add(8*time.Hour))); err != nil {
		t.Fatal(err)
	}
	m2 := NewManager(m.path, g, &fakeBackup{scheduled: map[string]time.Time{}})
	m2.now = func() time.Time { return c.wall.Add(-time.Hour) }
	m2.since = func(time.Time) time.Duration { return 0 }
	m2.Check(ctx)
	if g.members["alice"] {
		t.Fatal("not removed although the clock reads before the grant")
	}
}

func TestManager_AlreadyAdminAndExtension(t *testing.T) {
	m, g, b, c := testManager(t)
	ctx := context.Background()
	if _, err := m.Apply(ctx, true, grantReq("it", "g0", c.wall.Add(time.Hour))); !errors.Is(err, ErrAlreadyAdmin) {
		t.Fatalf("standing admin: %v", err)
	}
	if g.members["it"] != true || g.adds != 0 {
		t.Fatal("standing admin touched")
	}
	if _, err := m.Apply(ctx, true, grantReq("alice", "g1", c.wall.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	// an extension of the same grant is allowed although alice is an admin
	ext := c.wall.Add(5 * time.Hour)
	if _, err := m.Apply(ctx, true, grantReq("alice", "g1", ext)); err != nil {
		t.Fatalf("extend: %v", err)
	}
	if !b.scheduled["g1"].Equal(ext) {
		t.Fatalf("backup not moved: %v", b.scheduled)
	}
	c.wall = c.wall.Add(2 * time.Hour)
	m.Check(ctx)
	if !g.members["alice"] {
		t.Fatal("removed at the old end time")
	}
	if _, err := m.Apply(ctx, true, grantReq("bob", "g2", c.wall.Add(-time.Minute))); err == nil {
		t.Fatal("past expires_at accepted")
	}
}

func TestManager_FailedRemovalRetries(t *testing.T) {
	m, g, _, c := testManager(t)
	ctx := context.Background()
	if _, err := m.Apply(ctx, true, grantReq("alice", "g1", c.wall.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	g.removeErr = errors.New("alice is the last administrator")
	c.wall = c.wall.Add(time.Hour)
	m.Check(ctx)
	rep := Report(m.path, c.wall)
	if rep[0].State != GrantFailed || !strings.Contains(rep[0].Error, "last administrator") {
		t.Fatalf("%+v", rep)
	}
	n := g.removes
	m.Check(ctx) // backing off: no retry yet
	if g.removes != n {
		t.Fatal("retried without backing off")
	}
	g.removeErr = nil
	c.wall = c.wall.Add(31 * time.Second)
	m.Check(ctx)
	if g.members["alice"] || Report(m.path, c.wall)[0].State != GrantRemoved {
		t.Fatal("retry didn't remove")
	}
}

// The server's remove (End now, revoke, or its own expiry) ends the local
// grant and its backup task.
func TestManager_ServerRemove(t *testing.T) {
	m, g, b, c := testManager(t)
	ctx := context.Background()
	if _, err := m.Apply(ctx, true, grantReq("alice", "g1", c.wall.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	out, err := m.Apply(ctx, false, Request{Member: "alice", GrantID: "g1"})
	if err != nil || out.State != StateRemoved || g.members["alice"] {
		t.Fatalf("%+v %v", out, err)
	}
	if Report(m.path, c.wall)[0].State != GrantRemoved || len(b.cancelled) != 1 {
		t.Fatal("grant not ended")
	}
	if state, err := m.Expire(ctx, "g1"); err != nil || state != GrantRemoved {
		t.Fatalf("expire after removal: %q %v", state, err)
	}
	if _, err := m.Expire(ctx, "nope"); err == nil {
		t.Fatal("unknown grant expired")
	}
}

// The backup task's path: expire removes a due grant.
func TestManager_Expire(t *testing.T) {
	m, g, _, c := testManager(t)
	ctx := context.Background()
	if _, err := m.Apply(ctx, true, grantReq("alice", "g1", c.wall.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	if state, _ := m.Expire(ctx, "g1"); state != GrantActive || !g.members["alice"] {
		t.Fatalf("expired early: %q", state)
	}
	c.wall = c.wall.Add(time.Hour)
	if state, err := m.Expire(ctx, "g1"); err != nil || state != GrantRemoved || g.members["alice"] {
		t.Fatalf("%q %v", state, err)
	}
}

// Rights given but not recordable are taken back.
func TestManager_UnrecordableGrantIsUndone(t *testing.T) {
	m, g, _, c := testManager(t)
	m.path = filepath.Join(t.TempDir(), "missing-dir", StoreFile)
	_, err := m.Apply(context.Background(), true, grantReq("alice", "g1", c.wall.Add(time.Hour)))
	if err == nil || g.members["alice"] {
		t.Fatalf("err %v, member %v", err, g.members["alice"])
	}
}

func TestManager_BackupFailureIsANote(t *testing.T) {
	m, _, b, c := testManager(t)
	b.err = errors.New("no task scheduler")
	out, err := m.Apply(context.Background(), true, grantReq("alice", "g1", c.wall.Add(time.Hour)))
	if err != nil || out.Note == "" {
		t.Fatalf("%+v %v", out, err)
	}
}

func TestManager_PlainAddRecordsNothing(t *testing.T) {
	m, g, _, _ := testManager(t)
	if _, err := m.Apply(context.Background(), true, Request{Member: "alice"}); err != nil || !g.members["alice"] {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.path); !os.IsNotExist(err) {
		t.Fatal("a permanent grant was recorded")
	}
	if Report(m.path, time.Now()) != nil {
		t.Fatal("report not nil")
	}
}

func TestRetryDelay(t *testing.T) {
	if retryDelay(1) != 30*time.Second || retryDelay(3) != 2*time.Minute || retryDelay(50) != time.Hour {
		t.Fatal(retryDelay(1), retryDelay(3), retryDelay(50))
	}
}

func TestOutcomeJSON(t *testing.T) {
	n := 1
	got := Outcome{Success: true, State: StateRemoved, Member: "alice", SignedOut: &n}.JSON()
	if got != `{"Success":true,"State":"removed","Member":"alice","SignedOut":1}` {
		t.Fatal(got)
	}
}
