package logging

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckpointStore_LoadFreshWithNoFile(t *testing.T) {
	s := NewCheckpointStore(t.TempDir())
	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := s.Get(); len(got) != 0 {
		t.Errorf("Get() after fresh Load = %v, want empty", got)
	}
}

func TestCheckpointStore_SaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := NewCheckpointStore(dir)
	s.Update(CheckpointData{"windows_security": "12345", "journal": "cursor-abc"})

	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "checkpoints.json")); err != nil {
		t.Fatalf("checkpoint file not created: %v", err)
	}

	loaded := NewCheckpointStore(dir)
	if err := loaded.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := loaded.Get()
	if got["windows_security"] != "12345" || got["journal"] != "cursor-abc" {
		t.Errorf("Get() after round-trip = %v, want the saved values", got)
	}
}

func TestCheckpointStore_LoadCorruptFileFallsBackToEmpty(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "checkpoints.json"), []byte("{not json"), 0644); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}

	s := NewCheckpointStore(dir)
	if err := s.Load(); err != nil {
		t.Fatalf("Load on corrupt file should not error, got: %v", err)
	}
	if got := s.Get(); len(got) != 0 {
		t.Errorf("Get() after corrupt-file Load = %v, want empty", got)
	}
}

func TestCheckpointStore_GetReturnsDefensiveCopy(t *testing.T) {
	s := NewCheckpointStore(t.TempDir())
	s.Update(CheckpointData{"source": "value"})

	got := s.Get()
	got["source"] = "mutated"
	got["new-key"] = "should-not-leak"

	again := s.Get()
	if again["source"] != "value" {
		t.Errorf("mutating a Get() result affected the store: source = %v, want %q", again["source"], "value")
	}
	if _, exists := again["new-key"]; exists {
		t.Error("mutating a Get() result leaked a new key into the store")
	}
}

func TestCheckpointStore_UpdateMergesAndOverwrites(t *testing.T) {
	s := NewCheckpointStore(t.TempDir())
	s.Update(CheckpointData{"a": "1", "b": "2"})
	s.Update(CheckpointData{"b": "updated", "c": "3"})

	got := s.Get()
	want := CheckpointData{"a": "1", "b": "updated", "c": "3"}
	if len(got) != len(want) {
		t.Fatalf("Get() = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("Get()[%q] = %v, want %v", k, got[k], v)
		}
	}
}

func TestCheckpointStore_SaveCreatesMissingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "checkpoint-dir")
	s := NewCheckpointStore(dir)
	s.Update(CheckpointData{"k": "v"})

	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "checkpoints.json")); err != nil {
		t.Errorf("checkpoint file not created in nested dir: %v", err)
	}
}
