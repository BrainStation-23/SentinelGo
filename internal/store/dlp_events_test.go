package store

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sentinelgo/internal/dlp/events"
)

func newDLPStore(t *testing.T) (*DLPEventStore, *time.Time) {
	t.Helper()
	s, err := NewDLPEventStore(filepath.Join(t.TempDir(), DLPEventsDBName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	now := time.Unix(1_700_000_000, 0)
	s.now = func() time.Time { return now }
	return s, &now
}

func dlpEvent(content, policy string) events.Event {
	return events.Event{
		EventID: events.NewID(), Channel: "clipboard", PolicyID: policy, Action: events.ActionBlocked,
		ContentSHA256: content, RepeatCount: 1,
		Findings: []events.Finding{{Detector: "secrets.github-pat", Count: 1, Masked: "ghp_****abcd", SHA256: "h"}},
	}
}

func TestDLPEventStore_AddPendingDelete(t *testing.T) {
	s, _ := newDLPStore(t)
	for _, c := range []string{"a", "b", "c"} {
		if merged, err := s.Add(dlpEvent(c, "p1")); err != nil || merged {
			t.Fatalf("Add(%s) = %v, %v", c, merged, err)
		}
	}
	rows, err := s.Pending(2)
	if err != nil || len(rows) != 2 || rows[0].Event.ContentSHA256 != "a" || rows[1].Event.Findings[0].Masked != "ghp_****abcd" {
		t.Fatalf("Pending = %+v, %v", rows, err)
	}
	if err := s.Delete([]int64{rows[0].ID, rows[1].ID}); err != nil {
		t.Fatal(err)
	}
	if n, _, _, _ := s.Stats(); n != 1 {
		t.Errorf("rows after delete = %d, want 1", n)
	}
}

func TestDLPEventStore_DedupeWithinWindow(t *testing.T) {
	s, now := newDLPStore(t)
	first := dlpEvent("same", "p1")
	if _, err := s.Add(first); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(30 * time.Second)
	if merged, _ := s.Add(dlpEvent("same", "p1")); !merged {
		t.Error("repeat within 60 s not merged")
	}
	if merged, _ := s.Add(dlpEvent("same", "p2")); merged {
		t.Error("same content under another policy merged")
	}
	*now = now.Add(61 * time.Second)
	if merged, _ := s.Add(dlpEvent("same", "p1")); merged {
		t.Error("repeat after the window merged")
	}

	rows, _ := s.Pending(10)
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	if rows[0].Event.EventID != first.EventID || rows[0].Event.RepeatCount != 2 {
		t.Errorf("first row = %+v, want the original event with repeat_count 2", rows[0].Event)
	}
}

func TestDLPEventStore_CapDropsOldest(t *testing.T) {
	s, _ := newDLPStore(t)
	s.SetLimits(3, 1<<20)
	for i := range 5 {
		if _, err := s.Add(dlpEvent(string(rune('a'+i)), "p")); err != nil {
			t.Fatal(err)
		}
	}
	rows, _ := s.Pending(10)
	if len(rows) != 3 || rows[0].Event.ContentSHA256 != "c" {
		t.Errorf("rows = %d starting %q, want the 3 newest", len(rows), rows[0].Event.ContentSHA256)
	}
	if _, _, dropped, _ := s.Stats(); dropped != 2 {
		t.Errorf("dropped = %d, want 2", dropped)
	}

	// Byte cap: one big event pushes the older ones out.
	s.SetLimits(100, 3000)
	big := dlpEvent("big", "p")
	big.Excerpt = strings.Repeat("x", 2000)
	if _, err := s.Add(big); err != nil {
		t.Fatal(err)
	}
	_, bytes, dropped, _ := s.Stats()
	if bytes > 3000 || dropped < 3 {
		t.Errorf("bytes = %d dropped = %d; byte cap not enforced", bytes, dropped)
	}
}

func TestDLPEventStore_SurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), DLPEventsDBName)
	s, err := NewDLPEventStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(dlpEvent("a", "p")); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s2, err := NewDLPEventStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s2.Close() }()
	if rows, _ := s2.Pending(10); len(rows) != 1 {
		t.Errorf("rows after reopen = %d, want 1", len(rows))
	}
}

// A corrupt row is dropped without deadlocking the single-connection pool.
func TestDLPEventStore_CorruptRowDoesNotHang(t *testing.T) {
	s, _ := newDLPStore(t)
	if _, err := s.Add(dlpEvent("good", "p")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO dlp_event_queue (event_id, dedupe_key, event_json, bytes, stored_at) VALUES ('x', 'k', '{broken', 7, 0)`); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var rows []DLPEventRow
	go func() { rows, _ = s.Pending(10); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Pending deadlocked on a corrupt row")
	}
	if len(rows) != 1 {
		t.Errorf("rows = %d, want the good one", len(rows))
	}
	if n, _, _, _ := s.Stats(); n != 1 {
		t.Errorf("queue = %d rows, want the corrupt one deleted", n)
	}
}

// A repeat merged while a batch was uploading isn't lost.
func TestDLPEventStore_DeleteSentKeepsNewRepeats(t *testing.T) {
	s, now := newDLPStore(t)
	if _, err := s.Add(dlpEvent("c", "p")); err != nil {
		t.Fatal(err)
	}
	sent, _ := s.Pending(10) // repeat_count 1 goes out
	*now = now.Add(time.Second)
	if merged, _ := s.Add(dlpEvent("c", "p")); !merged { // a repeat during the upload
		t.Fatal("not merged")
	}
	if err := s.DeleteSent(sent); err != nil {
		t.Fatal(err)
	}
	rows, _ := s.Pending(10)
	if len(rows) != 1 || rows[0].Event.RepeatCount != 2 {
		t.Errorf("rows = %+v, want the row kept with repeat_count 2 for a resend", rows)
	}
	if err := s.DeleteSent(rows); err != nil {
		t.Fatal(err)
	}
	if n, _, _, _ := s.Stats(); n != 0 {
		t.Errorf("unchanged row not deleted (%d left)", n)
	}
}

// Different users copying the same content are separate events.
func TestDLPEventStore_DedupePerUser(t *testing.T) {
	s, _ := newDLPStore(t)
	a, b := dlpEvent("same", "p"), dlpEvent("same", "p")
	a.User, b.User = `CORP\alice`, `CORP\bob`
	if _, err := s.Add(a); err != nil {
		t.Fatal(err)
	}
	if merged, _ := s.Add(b); merged {
		t.Error("another user's copy merged into the first user's event")
	}
}
