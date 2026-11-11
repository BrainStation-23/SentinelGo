package scan

import (
	"os"
	"path/filepath"
	"testing"

	"sentinelgo/internal/store"
	"sentinelgo/internal/yara/ruleset"
)

func TestRemoveLocalData(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "config.json")
	files := []string{keep, filepath.Join(dir, StateFileName), filepath.Join(dir, SkipCacheFileName),
		filepath.Join(dir, StatusFileName), filepath.Join(dir, store.YARAEventsDBName),
		filepath.Join(dir, ruleset.DirName, "rules", "x.yar")}
	for _, f := range files {
		if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := RemoveLocalData(dir); err != nil {
		t.Fatal(err)
	}
	for _, f := range files[1:] {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("%s kept", f)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, ruleset.DirName)); !os.IsNotExist(err) {
		t.Error("ruleset cache folder kept")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Error("config.json removed")
	}
	if err := RemoveLocalData(dir); err != nil {
		t.Errorf("second run: %v", err)
	}
}
