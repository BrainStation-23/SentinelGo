package task

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
)

// maxResultFileBytes caps the result file a script may write; the backend
// accepts at most 16 KB too (sentinel-ops#49).
const maxResultFileBytes = 16 << 10

// readTaskResult builds a script task's structured result once the script
// has exited: whatever JSON object the script wrote to SENTINEL_RESULT_FILE,
// with exit_code always set by the agent from the process. A missing or
// unusable file gives just {"exit_code": N}; an unusable one is also
// mentioned at the end of the note. Without an exit code (the script never
// started, or was killed by a signal) there is no result.
func readTaskResult(path, note string, runErr error) (string, map[string]interface{}) {
	code, ok := exitCode(runErr)
	if !ok {
		return note, nil
	}
	result, problem := loadResultFile(path)
	if result == nil {
		result = map[string]interface{}{}
	}
	result["exit_code"] = code
	if problem != "" {
		log.Printf("Executor: %s", problem)
		note += "\n[agent] " + problem
	}
	return note, result
}

// exitCode returns the script's exit status. ok is false when there is none.
func exitCode(runErr error) (code int, ok bool) {
	if runErr == nil {
		return 0, true
	}
	var ee *exec.ExitError
	if errors.As(runErr, &ee) && ee.ExitCode() >= 0 {
		return ee.ExitCode(), true
	}
	return 0, false
}

// loadResultFile reads the script's result file. It returns nil and no
// problem when the script didn't write one.
func loadResultFile(path string) (map[string]interface{}, string) {
	// Lstat, not Stat: only a regular file the script wrote counts. A FIFO
	// would block the read, and a symlink could point anywhere.
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ""
	}
	if err != nil {
		return nil, fmt.Sprintf("result file ignored: %v", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, "result file ignored: not a regular file"
	}
	if fi.Size() > maxResultFileBytes {
		return nil, fmt.Sprintf("result file ignored: %d bytes, over the %d byte limit", fi.Size(), maxResultFileBytes)
	}

	// #nosec G304 - path is result.json inside the task's own temp dir
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Sprintf("result file ignored: %v", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxResultFileBytes+1))
	if err != nil {
		return nil, fmt.Sprintf("result file ignored: %v", err)
	}
	if len(data) > maxResultFileBytes {
		return nil, fmt.Sprintf("result file ignored: over the %d byte limit", maxResultFileBytes)
	}

	if !json.Valid(data) {
		return nil, "result file ignored: not valid JSON"
	}
	// UseNumber keeps large integers exact on the way back out.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var result map[string]interface{}
	if err := dec.Decode(&result); err != nil || result == nil {
		return nil, "result file ignored: not a JSON object"
	}
	return result, ""
}
