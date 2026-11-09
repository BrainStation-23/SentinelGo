package filedlp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"sentinelgo/internal/dlp/events"
	"sentinelgo/internal/dlp/ipc"
	"sentinelgo/internal/dlp/policy"
)

func syncBundle(files string) string {
	return `{"schema_version": 1, "version": "v1", "enabled": true,
  "modules": {"files": {"enabled": true, "channels": {"file.cloud_sync": true, "file.network_share": true}` + files + `}},
  "policies": [{"id": "p1", "name": "Secrets", "severity": "high", "channels": ["file.cloud_sync", "file.network_share"], "action": "block",
    "detectors": [{"id": "custom.keywords", "rule_id": "kw", "min_count": 1, "keywords": ["TOPSECRET"]}]}]}`
}

// openAsHelper opens path as the helper would, returning its handle.
func openAsHelper(t *testing.T, path string) windows.Handle {
	t.Helper()
	var unreadable atomic.Uint64
	h, _, st := openForDecision(path, &unreadable)
	if st != openOK {
		t.Fatalf("open %s: %v", path, st)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(h) })
	return h
}

// The service takes a sync folder file handed over by a "helper" (this
// process), decides it with the user from the helper's identity, and
// remediates through its own duplicated handle.
func TestTakeUserFile_SyncFolder(t *testing.T) {
	listVolumes = func() []winVolume { return nil }
	workerEnv = []string{workerTestEnv + "=serve"}
	t.Cleanup(func() { listVolumes, workerEnv = removableVolumes, nil })
	e, sink, cfgDir := startEnforcer(t, syncBundle(`, "audit_only": false, "copy_correlation": {"on_close_violation": "quarantine"}`))
	we := e.(*windowsEnforcer)
	eventually(t, "the enforcer", func() bool { h := e.Health(); return h != nil && h.State == stateRunning })
	if caps := e.Capabilities(); caps[policy.ChannelFileCloudSync] != "supported" || caps[policy.ChannelFileNetworkShare] != "supported" {
		t.Errorf("caps %v", caps)
	}
	dir := filepath.Join(t.TempDir(), "OneDrive")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "plan.txt")
	if err := os.WriteFile(path, []byte("the TOPSECRET plan"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := openAsHelper(t, path)
	from := ipc.Identity{PID: os.Getpid(), User: `CORP\ann`, SessionID: "3"}
	we.TakeUserFile(from, ipc.UserFile{ID: "1", Handle: uint64(h), Channel: policy.ChannelFileCloudSync, Root: dir, Label: "OneDrive\x07"})
	_ = windows.CloseHandle(h) // the helper closes its own after the ack
	eventually(t, "the event", func() bool { return len(sink.events()) == 1 })
	ev := sink.events()[0]
	if ev.Channel != policy.ChannelFileCloudSync || ev.User != `CORP\ann` || ev.SessionID != "3" ||
		ev.Destination.Type != TypeCloudSync || ev.Destination.VolumeLabel != "OneDrive" || ev.Action != events.ActionQuarantined {
		t.Errorf("event %+v dest %+v", ev, ev.Destination)
	}
	eventually(t, "the file removed", func() bool { _, err := os.Stat(path); return os.IsNotExist(err) })
	if q, _ := os.ReadDir(filepath.Join(cfgDir, QuarantineDir)); len(q) != 1 {
		t.Errorf("quarantine %v", q)
	}

	// A local file claimed to be on a share is refused: the handle says
	// where it is, not the helper.
	other := filepath.Join(dir, "other.txt")
	if err := os.WriteFile(other, []byte("TOPSECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	h2 := openAsHelper(t, other)
	we.TakeUserFile(from, ipc.UserFile{ID: "2", Handle: uint64(h2), Channel: policy.ChannelFileNetworkShare, Root: `Z:\`})
	// A channel the enforcer doesn't take, and a bad handle.
	we.TakeUserFile(from, ipc.UserFile{ID: "3", Handle: uint64(h2), Channel: policy.ChannelFileRemovable})
	we.TakeUserFile(from, ipc.UserFile{ID: "4", Handle: 0xdead, Channel: policy.ChannelFileCloudSync})
	time.Sleep(500 * time.Millisecond)
	if n := len(sink.events()); n != 1 {
		t.Errorf("%d events: a refused hand-off was decided", n)
	}
}

func TestUserDestination(t *testing.T) {
	share := ipc.UserFile{Channel: policy.ChannelFileNetworkShare}
	d, ok := userDestination(cleanFinalPath(`\\?\UNC\files.corp\Finance\q3\plan.xlsx`), share)
	if !ok || d.ShareHost != "files.corp" || d.Source != `\\files.corp\Finance` || d.Type != TypeNetworkShare {
		t.Errorf("share %+v %v", d, ok)
	}
	if _, ok := userDestination(`C:\Users\ann\x.txt`, share); ok {
		t.Error("a local path accepted as a share")
	}
	if _, ok := userDestination(`\\files.corp`, share); ok {
		t.Error("a server without a share accepted")
	}
	sync := ipc.UserFile{Channel: policy.ChannelFileCloudSync, Label: strings.Repeat("x", 100)}
	d, ok = userDestination(cleanFinalPath(`\\?\C:\Users\ann\OneDrive\a.txt`), sync)
	if !ok || d.Type != TypeCloudSync || d.Mount != `C:\` || len(d.VolumeLabel) != 64 {
		t.Errorf("sync %+v %v", d, ok)
	}
	if _, ok := userDestination(`\\server\share\a.txt`, sync); ok {
		t.Error("a share accepted as a sync folder")
	}
}

// recordingHandoff is the helper's sink, as the channel sees it.
type recordingHandoff struct {
	mu    sync.Mutex
	files []ipc.UserFile
}

func (r *recordingHandoff) Emit(events.Event) {}
func (r *recordingHandoff) HandOff(f ipc.UserFile, release func()) {
	r.mu.Lock()
	r.files = append(r.files, f)
	r.mu.Unlock()
	release()
}
func (r *recordingHandoff) got() []ipc.UserFile {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ipc.UserFile(nil), r.files...)
}

// The helper channel watches a sync folder and hands over each file once its
// writer is done; a trusted share is never watched.
func TestUserFolders_HandsOff(t *testing.T) {
	dir := t.TempDir() + `\`
	prevSync, prevShare, prevPoll, prevQuiet, prevTick := findSyncRoots, findShareRoots, rootsPoll, quietFor, pendingTick
	findSyncRoots = func() []userRoot {
		return []userRoot{{path: dir, label: "OneDrive", dest: Destination{Channel: policy.ChannelFileCloudSync, Type: TypeCloudSync, Mount: dir}}}
	}
	findShareRoots = func() []userRoot {
		return []userRoot{{path: dir, label: `\\nas\home`, dest: Destination{Channel: policy.ChannelFileNetworkShare, Type: TypeNetworkShare, Source: `\\nas\home`, ShareHost: "nas"}}}
	}
	rootsPoll, quietFor, pendingTick = 100*time.Millisecond, 200*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() {
		findSyncRoots, findShareRoots, rootsPoll, quietFor, pendingTick = prevSync, prevShare, prevPoll, prevQuiet, prevTick
	})
	c := compile(t, syncBundle(`, "trusted_shares": ["nas"]`))
	sink := &recordingHandoff{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{}, 2)
	for _, ch := range UserFolderChannels() {
		go func() { _ = ch.Run(ctx, c, sink); done <- struct{}{} }()
	}
	t.Cleanup(func() { cancel(); <-done; <-done })
	time.Sleep(300 * time.Millisecond) // the watches are up
	f, err := os.Create(filepath.Join(dir, "report.txt"))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("TOPSECRET")
	time.Sleep(600 * time.Millisecond)
	if n := len(sink.got()); n != 0 {
		t.Fatalf("handed over while still open for writing: %d", n)
	}
	_ = f.Close()
	eventually(t, "the hand-off", func() bool { return len(sink.got()) >= 1 })
	time.Sleep(300 * time.Millisecond)
	got := sink.got()
	if len(got) != 1 || got[0].Channel != policy.ChannelFileCloudSync || got[0].Label != "OneDrive" || got[0].Handle == 0 {
		t.Errorf("handed %+v (the trusted share must not be watched)", got)
	}
	// A sink that can't take files: the channel can't run.
	if err := UserFolderChannels()[0].Run(ctx, c, &recordingSink{}); err == nil {
		t.Error("ran without a hand-off sink")
	}
}
