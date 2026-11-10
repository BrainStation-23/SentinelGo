package filedlp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/dlp/policy"
)

func TestNormalizeUNC(t *testing.T) {
	for in, want := range map[string]string{
		`\\files.corp\Finance`:          `\\files.corp\Finance`,
		`\\files.corp\Finance\q3\a.txt`: `\\files.corp\Finance`,
		` \\nas\home\ `:                 `\\nas\home`,
		`\\nas`:                         "",
		`\\nas\`:                        "",
		`\\?\C:\x`:                      "",
		`\\.\pipe\x`:                    "",
		`Z:\x`:                          "",
		`http://dav/x`:                  "",
		``:                              "",
	} {
		got, ok := normalizeUNC(in)
		if got != want || ok != (want != "") {
			t.Errorf("normalizeUNC(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
}

func TestMountPointShare(t *testing.T) {
	for in, want := range map[string]string{
		`##files.corp#Finance`:                   `\\files.corp\Finance`,
		`##nas#home#sub`:                         `\\nas\home`,
		`##server@SSL#DavWWWRoot`:                `\\server@SSL\DavWWWRoot`,
		`{a1b2c3d4-0000-0000-0000-000000000000}`: "",
		`E`:                                      "",
		`##nas`:                                  "",
	} {
		got, ok := mountPointShare(in)
		if got != want || ok != (want != "") {
			t.Errorf("mountPointShare(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
}

// Shares by path come live connections first, without duplicates or those
// a drive is mapped to, and at most maxUNCWatches.
func TestUNCShares(t *testing.T) {
	drives := []userRoot{{path: `Z:\`, label: `\\nas\home`}}
	src := uncShareSources{
		connected:  func() []string { return []string{`\\NAS\home`, `\\files.corp\Finance`, `Y:`} },
		persistent: func() []string { return []string{`\\files.corp\finance`, `\\backup\it`} },
		recent:     nil,
	}
	got := uncShares(src, drives)
	if len(got) != 2 || got[0].path != `\\files.corp\Finance\` || got[1].path != `\\backup\it\` {
		t.Fatalf("roots %+v", got)
	}
	d := got[0].dest
	if d.Channel != policy.ChannelFileNetworkShare || d.Type != TypeNetworkShare || d.ShareHost != "files.corp" ||
		d.Source != `\\files.corp\Finance` || got[0].label != `\\files.corp\Finance` {
		t.Errorf("dest %+v", d)
	}

	var many []string
	for i := range maxUNCWatches + 5 {
		many = append(many, `\\srv`+string(rune('a'+i))+`\share`)
	}
	got = uncShares(uncShareSources{recent: func() []string { return many }}, nil)
	if len(got) != maxUNCWatches {
		t.Errorf("%d roots, want the cap %d", len(got), maxUNCWatches)
	}
}

func TestMupPath(t *testing.T) {
	for in, want := range map[string]string{
		`\Device\Mup\files.corp\Finance\q3\plan.xlsx`:                          `\\files.corp\Finance\q3\plan.xlsx`,
		`\device\mup\nas\home\a.txt`:                                           `\\nas\home\a.txt`,
		`\Device\Mup\;LanmanRedirector\;Z:000000000001a2b3\nas\home\a.txt`:     `\\nas\home\a.txt`,
		`\Device\Mup\;WebDavRedirector\;Y:0000000000000001\dav\DavWWWRoot\x.d`: `\\dav\DavWWWRoot\x.d`,
		`\Device\Mup\nas\home`:                                                 "", // the share itself, not a file in it
		`\Device\Mup\nas`:                                                      "",
		`\Device\Mup\;LanmanRedirector`:                                        "",
		`\Device\Mup\`:                                                         "",
		`\Device\HarddiskVolume3\Users\ann\plan.txt`:                           "",
		`\Device\Mupx\nas\home\a.txt`:                                          "",
	} {
		got, ok := mupPath(in)
		if got != want || ok != (want != "") {
			t.Errorf("mupPath(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
}

// Writes on shares and in learned sync folders are attributed; a sync
// folder under a profile is still a taint source.
func TestWinTaint_SharesAndSyncFolders(t *testing.T) {
	tk := &winTaint{store: newTaintStore(), writers: map[string]writerRef{}, profiles: `c:\users\`}
	devs := []ntPrefix{{nt: `\Device\HarddiskVolume3`, dos: "C:"}}
	tk.devices.Store(&devs)
	tk.watched.Store(&[]string{})
	tk.syncs.Store(&[]string{`c:\users\ann\onedrive\`})

	tk.onOpen(fileOpen{pid: 7, path: `\Device\Mup\;LanmanRedirector\;Z:0000000000001234\nas\home\out.docx`})
	tk.onOpen(fileOpen{pid: 8, path: `\Device\HarddiskVolume3\Users\ann\OneDrive\report.txt`})
	tk.onOpen(fileOpen{pid: 9, path: `\Device\HarddiskVolume3\Users\ann\Documents\plan.txt`})
	now := time.Now()
	if pid, ok := tk.writer(`\\NAS\home\out.docx`, now, time.Minute); !ok || pid != 7 {
		t.Errorf("share writer %d %v", pid, ok)
	}
	if pid, ok := tk.writer(`C:\Users\ann\OneDrive\report.txt`, now, time.Minute); !ok || pid != 8 {
		t.Errorf("sync writer %d %v", pid, ok)
	}
	if _, ok := tk.writer(`C:\Users\ann\Documents\plan.txt`, now, time.Minute); ok {
		t.Error("a profile file outside the sync folder recorded as written")
	}
	if src := tk.store.sources(8, time.Time{}, now, time.Minute); len(src) != 1 {
		t.Errorf("the sync folder file isn't a source: %+v", src)
	}
	if src := tk.store.sources(7, time.Time{}, now, time.Minute); len(src) != 0 {
		t.Errorf("a share file is a source: %+v", src)
	}
}

func TestSyncRootOf(t *testing.T) {
	const profiles = `c:\users\`
	cases := []struct {
		path, claimed, want string
	}{
		{`C:\Users\ann\OneDrive\a.txt`, `C:\Users\ann\OneDrive`, `c:\users\ann\onedrive\`},
		{`C:\Users\ann\OneDrive - Corp\x\a.txt`, `C:\Users\ann\OneDrive - Corp\`, `c:\users\ann\onedrive - corp\`},
		{`G:\My Drive\a.txt`, `G:\`, `g:\`},
		{`C:\Users\ann\OneDrive\a.txt`, `C:\Users\ann`, ""},          // a whole profile
		{`C:\Users\ann\OneDrive\a.txt`, `C:\Users`, ""},              // the profiles folder
		{`C:\Users\ann\OneDrive\a.txt`, `C:\`, ""},                   // the system drive
		{`C:\Users\ann\OneDrive\a.txt`, `C:\Users\bob\OneDrive`, ""}, // not where the file is
		{`C:\Users\ann\OneDriveX\a.txt`, `C:\Users\ann\OneDrive`, ""},
		{`\\nas\home\a.txt`, `\\nas\home`, ""},
		{`C:\Users\ann\OneDrive\a.txt`, ``, ""},
	}
	for _, c := range cases {
		got, ok := syncRootOf(c.path, c.claimed, profiles)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("syncRootOf(%q, %q) = %q %v, want %q", c.path, c.claimed, got, ok, c.want)
		}
	}
}

// A root that can't be watched (a server that's gone) is tried again only
// after rootRetry, and doesn't hold up the others.
func TestUserWatcher_RetriesFailedRoot(t *testing.T) {
	var mu sync.Mutex
	starts := map[string]int{}
	prevStart, prevShare := startUserWatch, findShareRoots
	startUserWatch = func(root string, _ func(fsChange), _ func(string), _ func(string)) (*dirWatch, error) {
		mu.Lock()
		starts[root]++
		mu.Unlock()
		return nil, errors.New("the network path was not found")
	}
	findShareRoots = func() []userRoot { return []userRoot{uncRoot(`\\gone\share`)} }
	t.Cleanup(func() { startUserWatch, findShareRoots = prevStart, prevShare })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := newUserWatcher(policy.ChannelFileNetworkShare, policy.FilesModule{}, nil)
	now := time.Now()
	w.reconcile(ctx, now)
	w.onStarted(<-w.started, now)
	w.reconcile(ctx, now.Add(rootsPoll))
	select {
	case res := <-w.started:
		t.Fatalf("started again within rootRetry: %+v", res)
	case <-time.After(100 * time.Millisecond):
	}
	w.reconcile(ctx, now.Add(rootRetry+time.Second))
	w.onStarted(<-w.started, now)
	mu.Lock()
	defer mu.Unlock()
	if starts[`\\gone\share\`] != 2 {
		t.Errorf("starts %v", starts)
	}
	if len(w.watches) != 0 || len(w.start) != 0 {
		t.Errorf("watches %v starting %v", w.watches, w.start)
	}
}

// A watch whose share goes away is dropped and retried later; one reported
// lost before its start arrived is not kept either.
func TestUserWatcher_LostWatch(t *testing.T) {
	dir := t.TempDir() + `\`
	prevShare := findShareRoots
	findShareRoots = func() []userRoot { return []userRoot{{path: dir, label: `\\nas\home`}} }
	t.Cleanup(func() { findShareRoots = prevShare })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := newUserWatcher(policy.ChannelFileNetworkShare, policy.FilesModule{}, nil)
	now := time.Now()
	w.reconcile(ctx, now)
	res := <-w.started
	w.onStarted(res, now)
	if len(w.watches) != 1 {
		t.Fatalf("watches %v", w.watches)
	}
	w.onLost(res.tok, now)
	if len(w.watches) != 0 || w.retry[strings.ToLower(dir)].IsZero() {
		t.Errorf("lost watch kept: watches %v retry %v", w.watches, w.retry)
	}

	w.reconcile(ctx, now.Add(rootRetry+time.Second))
	res = <-w.started
	res.tok.gone.Store(true) // its loop ended before the start was handled
	w.onStarted(res, now)
	if len(w.watches) != 0 {
		t.Errorf("a watch already gone was kept: %v", w.watches)
	}
}

// The real sources run as this user (most machines have no shares): every
// root they give is a share's.
func TestShareRoots_RealSources(t *testing.T) {
	for _, r := range shareRoots() {
		if r.dest.Channel != policy.ChannelFileNetworkShare || r.dest.Type != TypeNetworkShare || r.path == "" {
			t.Errorf("root %+v", r)
		}
	}
}

// Learned sync folders are bounded, and a taint running when one is learned
// gets it.
func TestLearnSyncRoot_Bounded(t *testing.T) {
	e := &windowsEnforcer{}
	tk := &winTaint{store: newTaintStore(), writers: map[string]writerRef{}}
	e.taint.Store(tk)
	for i := range maxSyncRoots + 3 {
		root := `D:\Sync` + string(rune('A'+i/26)) + string(rune('a'+i%26))
		e.learnSyncRoot(root+`\a.txt`, root)
	}
	if n := len(*e.syncRootList()); n != maxSyncRoots {
		t.Fatalf("%d roots, want %d", n, maxSyncRoots)
	}
	if n := len(*tk.syncs.Load()); n != maxSyncRoots {
		t.Errorf("the taint has %d roots", n)
	}
	e.learnSyncRoot(`D:\Other\a.txt`, `D:\Sync`) // not where the file is
	if n := len(*e.syncRootList()); n != maxSyncRoots {
		t.Errorf("%d roots", n)
	}
}
