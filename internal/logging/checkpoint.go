package logging

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// CheckpointData holds per-source checkpoint values.
// Keys are source names (e.g. "windows_security", "journal", "auth.log").
// Values are source-specific (record ID, cursor string, file offset, etc.).
type CheckpointData map[string]interface{}

// CheckpointStore persists and loads checkpoint data from a JSON file.
// Writes are atomic (write to .tmp, then rename) to prevent corruption.
type CheckpointStore struct {
	mu   sync.Mutex
	path string
	data CheckpointData
}

// NewCheckpointStore creates a store that reads/writes to the given directory.
// The checkpoint file is named "checkpoints.json" inside dir.
func NewCheckpointStore(dir string) *CheckpointStore {
	return &CheckpointStore{
		path: filepath.Join(dir, "checkpoints.json"),
		data: make(CheckpointData),
	}
}

// Load reads checkpoint data from disk. If the file does not exist,
// an empty checkpoint is used (fresh start). Corrupt files are logged
// and treated as empty.
func (s *CheckpointStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.data = make(CheckpointData)
			return nil
		}
		return fmt.Errorf("read checkpoint file: %w", err)
	}

	var data CheckpointData
	if err := json.Unmarshal(raw, &data); err != nil {
		// Corrupt file -- start fresh
		s.data = make(CheckpointData)
		return nil
	}

	s.data = data
	return nil
}

// Save persists the current checkpoint data to disk atomically.
func (s *CheckpointStore) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal checkpoint: %w", err)
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create checkpoint dir: %w", err)
	}

	tmp := s.path + ".tmp"
	// #nosec G306 - Checkpoint files need to be readable by the service
	if err := os.WriteFile(tmp, raw, 0644); err != nil {
		return fmt.Errorf("write checkpoint tmp: %w", err)
	}

	if err := os.Rename(tmp, s.path); err != nil {
		if rerr := os.Remove(tmp); rerr != nil {
			// Log error but continue
			_ = rerr
		}
		return fmt.Errorf("rename checkpoint: %w", err)
	}

	return nil
}

// Get returns the current checkpoint data (a copy).
func (s *CheckpointStore) Get() CheckpointData {
	s.mu.Lock()
	defer s.mu.Unlock()

	cp := make(CheckpointData, len(s.data))
	for k, v := range s.data {
		cp[k] = v
	}
	return cp
}

// Update merges new checkpoint values into the store.
// Existing keys are overwritten; new keys are added.
func (s *CheckpointStore) Update(updates CheckpointData) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for k, v := range updates {
		s.data[k] = v
	}
}
