package task

// White-box tests for task artifacts in runTask (#137): validation, fetch,
// what the script sees (env and payload.json), and that a bad file stops the
// script from running.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"sentinelgo/internal/artifact"
	"sentinelgo/internal/taskstore"
)

const installerBytes = "INSTALLER-BYTES-v1"

func installerSpec(body string) artifact.Spec {
	h := sha256.Sum256([]byte(body))
	return artifact.Spec{
		ID:       "installer",
		Bucket:   "app-installers",
		Path:     "artifacts/7f3c/ZoomInstallerFull.msi",
		Filename: "ZoomInstallerFull.msi",
		SHA256:   hex.EncodeToString(h[:]),
		Size:     int64(len(body)),
	}
}

// artifactServer serves served for every app-installers object and counts
// the requests.
func artifactServer(t *testing.T, served string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if !strings.HasPrefix(r.URL.Path, "/storage/v1/object/authenticated/app-installers/") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(served))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// reportScript prints what the script can see: the task env vars, the
// installer's contents, and payload.json on the last line.
func reportScript() (name, body string) {
	if runtime.GOOS == "windows" {
		return "report.cmd", "@echo TASKID=%SENTINEL_TASK_ID%\r\n" +
			"@echo TASKDIR=%SENTINEL_TASK_DIR%\r\n" +
			"@echo ARTDIR=%SENTINEL_ARTIFACTS_DIR%\r\n" +
			"@echo ARTIFACT=%SENTINEL_ARTIFACT_INSTALLER%\r\n" +
			"@if defined SENTINEL_ARTIFACT_INSTALLER type \"%SENTINEL_ARTIFACT_INSTALLER%\"\r\n" +
			"@echo.\r\n" +
			"@type \"%1\"\r\n"
	}
	return "report.sh", "echo \"TASKID=$SENTINEL_TASK_ID\"\n" +
		"echo \"TASKDIR=$SENTINEL_TASK_DIR\"\n" +
		"echo \"ARTDIR=$SENTINEL_ARTIFACTS_DIR\"\n" +
		"echo \"ARTIFACT=$SENTINEL_ARTIFACT_INSTALLER\"\n" +
		"if [ -n \"$SENTINEL_ARTIFACT_INSTALLER\" ]; then cat \"$SENTINEL_ARTIFACT_INSTALLER\"; fi\n" +
		"echo\n" +
		"cat \"$1\"\n"
}

func artifactTask(payload map[string]interface{}, specs ...artifact.Spec) taskstore.Task {
	name, body := reportScript()
	return taskstore.Task{
		ID:      "t1",
		Slug:    "install-package",
		Payload: payload,
		Scripts: map[string]interface{}{
			runtime.GOOS: map[string]interface{}{"filename": name, "body": body},
		},
		Artifacts: specs,
	}
}

// field returns the value after "KEY=" on its own output line.
func field(out, key string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if v, ok := strings.CutPrefix(line, key+"="); ok {
			return v
		}
	}
	return ""
}

// lastLine is the payload.json the script printed last.
func lastLine(out string) string {
	lines := strings.Split(strings.TrimRight(out, "\r\n"), "\n")
	return strings.TrimRight(lines[len(lines)-1], "\r")
}

func TestRunTask_Artifacts_HappyPath(t *testing.T) {
	tmp := isolateTempDir(t)
	srv, hits := artifactServer(t, installerBytes)
	s, _ := newExecutorFixture(t, &fakeTaskClient{}, srv.URL)

	task := artifactTask(map[string]interface{}{"k": "v", "artifacts": "server value is replaced"}, installerSpec(installerBytes))
	out, err := s.runTask(context.Background(), task)
	if err != nil {
		t.Fatalf("runTask: %v (output %q)", err, out)
	}
	if hits.Load() != 1 {
		t.Errorf("artifact requests = %d, want 1", hits.Load())
	}

	taskDir := field(out, "TASKDIR")
	if field(out, "TASKID") != "t1" || taskDir == "" {
		t.Fatalf("task env missing from output %q", out)
	}
	wantDir := filepath.Join(taskDir, "artifacts")
	if got := field(out, "ARTDIR"); got != wantDir {
		t.Errorf("SENTINEL_ARTIFACTS_DIR = %q, want %q", got, wantDir)
	}
	artPath := field(out, "ARTIFACT")
	if artPath != filepath.Join(wantDir, "ZoomInstallerFull.msi") {
		t.Errorf("SENTINEL_ARTIFACT_INSTALLER = %q, want it under %q", artPath, wantDir)
	}
	if !strings.Contains(out, installerBytes) {
		t.Errorf("script could not read the installer; output %q", out)
	}

	var payload struct {
		K         string `json:"k"`
		Artifacts map[string]struct {
			Path, Filename, SHA256 string
			Size                   int64
		} `json:"artifacts"`
	}
	if err := json.Unmarshal([]byte(lastLine(out)), &payload); err != nil {
		t.Fatalf("payload.json %q: %v", lastLine(out), err)
	}
	got := payload.Artifacts["installer"]
	spec := installerSpec(installerBytes)
	if payload.K != "v" || got.Path != artPath || got.Filename != spec.Filename || got.SHA256 != spec.SHA256 || got.Size != spec.Size {
		t.Errorf("payload = %+v, want k=v and artifacts.installer at %q", payload, artPath)
	}
	assertNoTaskTempDirs(t, tmp)
}

// TestRunTask_NoArtifacts_Unchanged: without artifacts nothing is fetched and
// payload.json is exactly the task payload, as before (#137 regression).
func TestRunTask_NoArtifacts_Unchanged(t *testing.T) {
	isolateTempDir(t)
	srv, hits := artifactServer(t, installerBytes)
	s, _ := newExecutorFixture(t, &fakeTaskClient{}, srv.URL)

	payload := map[string]interface{}{"k": "v", "artifacts": "left alone"}
	out, err := s.runTask(context.Background(), artifactTask(payload))
	if err != nil {
		t.Fatalf("runTask: %v (output %q)", err, out)
	}
	if hits.Load() != 0 {
		t.Errorf("requests = %d, want 0", hits.Load())
	}
	want, _ := json.Marshal(payload)
	if got := lastLine(out); got != string(want) {
		t.Errorf("payload.json = %q, want %q", got, want)
	}
	if field(out, "TASKID") != "t1" || field(out, "ARTIFACT") != "" {
		t.Errorf("env: want SENTINEL_TASK_ID set and no artifact var; output %q", out)
	}
}

func TestRunTask_Artifacts_ValidationFails_ScriptNotRun(t *testing.T) {
	tmp := isolateTempDir(t)
	srv, hits := artifactServer(t, installerBytes)
	s, _ := newExecutorFixture(t, &fakeTaskClient{}, srv.URL)

	bad := installerSpec(installerBytes)
	bad.Bucket = "command-scripts"
	out, err := s.runTask(context.Background(), artifactTask(nil, bad))
	if err == nil || !strings.Contains(err.Error(), "invalid task artifacts") {
		t.Fatalf("err = %v, want an artifact validation error", err)
	}
	if out != "" || hits.Load() != 0 {
		t.Errorf("output %q, requests %d; want the script not run and nothing fetched", out, hits.Load())
	}
	assertNoTaskTempDirs(t, tmp)
}

func TestRunTask_Artifacts_HashMismatch_ScriptNotRun(t *testing.T) {
	tmp := isolateTempDir(t)
	srv, _ := artifactServer(t, "TAMPERED-BYTES-v1!")
	s, _ := newExecutorFixture(t, &fakeTaskClient{}, srv.URL)

	out, err := s.runTask(context.Background(), artifactTask(nil, installerSpec(installerBytes)))
	if err == nil {
		t.Fatalf("runTask succeeded with a tampered installer (output %q)", out)
	}
	for _, want := range []string{"fetch artifacts", "installer", "sha256 mismatch"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to mention %q", err, want)
		}
	}
	if out != "" {
		t.Errorf("script ran: output %q", out)
	}
	assertNoTaskTempDirs(t, tmp)
}

func TestExecuteTask_Artifacts_FailureNoteNamesArtifact(t *testing.T) {
	isolateTempDir(t)
	srv, _ := artifactServer(t, "short")
	client := &fakeTaskClient{}
	s, _ := newExecutorFixture(t, client, srv.URL)
	tk := artifactTask(nil, installerSpec(installerBytes))
	seedTasks(t, s.pollingSvc, tk)

	s.executeTask(context.Background(), tk)

	u := client.recorded()
	if len(u) != 1 || u[0].status != "failed" || !strings.Contains(u[0].note, "artifact installer") || !strings.Contains(u[0].note, "size mismatch") {
		t.Errorf("reported %+v, want one failure naming the artifact and the size mismatch", u)
	}
}

func TestRunTask_NativeSlugWithArtifacts_Fails(t *testing.T) {
	s, _ := newExecutorFixture(t, &fakeTaskClient{}, "")
	ran := false
	s.nativeHandlers["test-native"] = func(context.Context, taskstore.Task) (string, error) {
		ran = true
		return "", nil
	}
	_, err := s.runTask(context.Background(), taskstore.Task{ID: "t1", Slug: "test-native", Artifacts: []artifact.Spec{installerSpec("x")}})
	if err == nil || !strings.Contains(err.Error(), "only supported for script tasks") {
		t.Fatalf("err = %v", err)
	}
	if ran {
		t.Error("native handler ran despite artifacts")
	}
}

func TestScriptEnv(t *testing.T) {
	task := taskstore.Task{ID: "t9", Artifacts: []artifact.Spec{{ID: "installer"}, {ID: "config_2"}}}
	got := scriptEnv(task, "/tmp/d", "/tmp/d/artifacts", map[string]string{"installer": "/tmp/d/artifacts/a.msi", "config_2": "/tmp/d/artifacts/c.json"})
	want := []string{
		"SENTINEL_TASK_ID=t9",
		"SENTINEL_TASK_DIR=/tmp/d",
		"SENTINEL_ARTIFACTS_DIR=/tmp/d/artifacts",
		"SENTINEL_ARTIFACT_INSTALLER=/tmp/d/artifacts/a.msi",
		"SENTINEL_ARTIFACT_CONFIG_2=/tmp/d/artifacts/c.json",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("scriptEnv = %q, want %q", got, want)
	}
}
