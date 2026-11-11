package scan

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"sentinelgo/internal/store"
	"sentinelgo/internal/yara/ruleset"
)

// RemoveLocalData deletes everything threat hunting keeps in dir (the
// folder of config.json), for `sentinelgo -uninstall` (#416): the ruleset
// cache, the scan state and skip cache, the local status and the event
// queue (with any events not yet uploaded). Missing files are not errors.
func RemoveLocalData(dir string) error {
	var errs []error
	if err := os.RemoveAll(filepath.Join(dir, ruleset.DirName)); err != nil {
		errs = append(errs, err)
	}
	for _, name := range []string{StateFileName, SkipCacheFileName, StatusFileName,
		store.YARAEventsDBName, store.YARAEventsDBName + "-wal", store.YARAEventsDBName + "-shm"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
