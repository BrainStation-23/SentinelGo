package software

import "testing"

func TestDedupeHomes_EmptyStringSkipped(t *testing.T) {
	seen := map[string]bool{}
	got := dedupeHomes(nil, seen, "")
	if len(got) != 0 {
		t.Errorf("dedupeHomes with empty home = %v, want empty", got)
	}
}

func TestDedupeHomes_AddsNewHome(t *testing.T) {
	seen := map[string]bool{}
	got := dedupeHomes(nil, seen, "/home/alice")
	if len(got) != 1 || got[0] != "/home/alice" {
		t.Errorf("dedupeHomes() = %v, want [\"/home/alice\"]", got)
	}
	if !seen["/home/alice"] {
		t.Error("seen map not updated with new home")
	}
}

func TestDedupeHomes_SkipsDuplicate(t *testing.T) {
	seen := map[string]bool{"/home/alice": true}
	got := dedupeHomes([]string{"/home/alice"}, seen, "/home/alice")
	if len(got) != 1 {
		t.Errorf("dedupeHomes() = %v, want unchanged single-element slice", got)
	}
}

func TestDedupeHomes_AppendsToExisting(t *testing.T) {
	seen := map[string]bool{"/home/alice": true}
	got := dedupeHomes([]string{"/home/alice"}, seen, "/home/bob")
	want := []string{"/home/alice", "/home/bob"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("dedupeHomes() = %v, want %v", got, want)
	}
	if !seen["/home/bob"] {
		t.Error("seen map not updated with new home")
	}
}
