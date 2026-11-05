package localadmin

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSystemdBackup(t *testing.T) {
	dir := t.TempDir()
	f := newFake()
	f.out["systemctl daemon-reload"] = ""
	f.out["systemctl enable --now sentinelgo-local-admin-g1.timer"] = ""
	f.out["systemctl disable --now sentinelgo-local-admin-g1.timer"] = ""
	b := &systemdBackup{run: f.run, exe: "/opt/sentinelgo/sentinel go", dir: dir}
	at := time.Date(2026, 11, 4, 15, 0, 30, 0, time.FixedZone("x", 6*3600))
	if err := b.Schedule(context.Background(), "g1", at); err != nil {
		t.Fatal(err)
	}
	svc, _ := os.ReadFile(filepath.Join(dir, "sentinelgo-local-admin-g1.service"))
	tmr, _ := os.ReadFile(filepath.Join(dir, "sentinelgo-local-admin-g1.timer"))
	if !strings.Contains(string(svc), `ExecStart="/opt/sentinelgo/sentinel go" "local-admin" "expire" "g1"`) {
		t.Fatalf("service:\n%s", svc)
	}
	if !strings.Contains(string(tmr), "OnCalendar=2026-11-04 09:00:30 UTC") || !strings.Contains(string(tmr), "Persistent=true") {
		t.Fatalf("timer:\n%s", tmr)
	}
	if err := b.Cancel(context.Background(), "g1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sentinelgo-local-admin-g1.timer")); !os.IsNotExist(err) {
		t.Fatal("timer left behind")
	}
	if err := b.Schedule(context.Background(), "../x", at); err == nil {
		t.Fatal("bad id accepted")
	}
}

func TestLaunchdBackup(t *testing.T) {
	dir := t.TempDir()
	f := newFake()
	p := filepath.Join(dir, "com.sentinelgo.localadmin.g1.plist")
	f.out["launchctl bootstrap system "+p] = ""
	b := &launchdBackup{run: f.run, exe: "/opt/sentinelgo/sentinelgo&co", dir: dir}
	at := time.Date(2026, 3, 9, 23, 59, 1, 0, time.Local)
	if err := b.Schedule(context.Background(), "g1", at); err != nil {
		t.Fatal(err)
	}
	pl, _ := os.ReadFile(p)
	s := string(pl)
	// rounded up to the next minute: 10 March 00:00
	for _, want := range []string{"<string>com.sentinelgo.localadmin.g1</string>", "<string>/opt/sentinelgo/sentinelgo&amp;co</string>",
		"<key>Month</key><integer>3</integer>", "<key>Day</key><integer>10</integer>", "<key>Hour</key><integer>0</integer>", "<key>Minute</key><integer>0</integer>"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in\n%s", want, s)
		}
	}
	if err := b.Cancel(context.Background(), "g1"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) || !f.called("launchctl bootout system/com.sentinelgo.localadmin.g1") {
		t.Fatal("not cancelled")
	}
}

func TestWinBackup(t *testing.T) {
	f := newFake()
	f.out["powershell schedule"] = ""
	f.out["powershell cancel"] = ""
	b := &winBackup{run: f.run, exe: `C:\sentinelgo\sentinelgo.exe`}
	at := time.Date(2026, 11, 4, 15, 0, 0, 0, time.FixedZone("x", 3600))
	if err := b.Schedule(context.Background(), "g1", at); err != nil {
		t.Fatal(err)
	}
	env := strings.Join(f.envs[0], "|")
	if env != `SG_AT=2026-11-04T14:00:00Z|SG_EXE=C:\sentinelgo\sentinelgo.exe|SG_GRANT=g1` {
		t.Fatal(env)
	}
	if err := b.Cancel(context.Background(), "g1"); err != nil {
		t.Fatal(err)
	}
	if BackupFor("plan9", f.run, "x") == nil {
		t.Fatal("nil backup")
	}
}
