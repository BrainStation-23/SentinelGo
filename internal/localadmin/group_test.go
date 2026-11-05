package localadmin

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeRun answers commands by their joined command line; a prefix match on
// "tool arg..." is enough. Unknown commands fail like a missing tool.
type fakeRun struct {
	out   map[string]string
	fail  map[string]bool
	calls []string
	envs  [][]string
}

func newFake() *fakeRun { return &fakeRun{out: map[string]string{}, fail: map[string]bool{}} }

func (f *fakeRun) run(_ context.Context, tool string, args []string, env []string) (string, error) {
	line := tool + " " + strings.Join(args, " ")
	if tool == "powershell" {
		line = "powershell " + psKind(args[len(args)-1])
	}
	f.calls = append(f.calls, line)
	f.envs = append(f.envs, env)
	for k := range f.fail {
		if strings.HasPrefix(line, k) {
			return "", &ExitError{Tool: tool, Code: 1, Stderr: "failed"}
		}
	}
	for k, v := range f.out {
		if line == k {
			return v, nil
		}
	}
	return "", &ExitError{Tool: tool, Code: 1}
}

func (f *fakeRun) called(prefix string) bool {
	for _, c := range f.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func psKind(script string) string {
	switch script {
	case winListScript:
		return "list"
	case winAddScript:
		return "add"
	case winRemoveScript:
		return "remove"
	case winScheduleScript:
		return "schedule"
	case winCancelScript:
		return "cancel"
	}
	return "?"
}

func TestParseRequest(t *testing.T) {
	r, err := ParseRequest(map[string]interface{}{"member": "alice", "sid": "S-1-5-21-1-2-3-1001", "source": "Local",
		"sign_out": true, "grant_id": "9b2f-11", "expires_at": "2026-11-04T15:00:00Z", "other": 1}, true)
	if err != nil || r.Member != "alice" || r.Source != "local" || !r.SignOut || r.ExpiresAt == nil || r.ExpiresAt.Hour() != 15 {
		t.Fatalf("%+v %v", r, err)
	}
	bad := []map[string]interface{}{
		{},
		{"member": 5},
		{"member": "a\nb"},
		{"member": "a", "sid": "S-1-x"},
		{"member": "a", "source": "cloud"},
		{"member": "a", "grant_id": "../x"},
		{"member": "a", "expires_at": "tomorrow", "grant_id": "g"},
		{"member": "a", "expires_at": "2026-11-04T15:00:00Z"}, // no grant id
	}
	for _, p := range bad {
		if _, err := ParseRequest(p, true); err == nil {
			t.Errorf("%v: accepted", p)
		}
	}
	if _, err := ParseRequest(map[string]interface{}{"member": "a", "grant_id": "g", "expires_at": "2026-11-04T15:00:00Z"}, false); err == nil {
		t.Error("expires_at accepted on remove")
	}
}

func TestUnixName(t *testing.T) {
	for in, want := range map[string]string{`CONTOSO\alice`: "alice", "bob.smith@x": "bob.smith@x"} {
		if got, err := unixName(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, in := range []string{"", "-rf", "a b", "a;b", "$(id)"} {
		if _, err := unixName(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

// ── Windows ──────────────────────────────────────────────────────────────────

const winRoster = `[{"name":"PC\\Administrator","sid":"S-1-5-21-1-2-3-500","source":"Local","class":"User","enabled":false},
{"name":"PC\\it","sid":"S-1-5-21-1-2-3-1000","source":"Local","class":"User","enabled":true},
{"name":"PC\\alice","sid":"S-1-5-21-1-2-3-1001","source":"Local","class":"User","enabled":true},
{"name":"CONTOSO\\Domain Admins","sid":"S-1-5-21-9-9-9-512","source":"ActiveDirectory","class":"Group","enabled":true}]`

func winGroup(f *fakeRun) *windowsGroup {
	return &windowsGroup{run: f.run, signOut: func(_ context.Context, user string) (int, error) {
		f.calls = append(f.calls, "signout "+user)
		return 2, nil
	}}
}

func TestWindows_AddAndAlready(t *testing.T) {
	f := newFake()
	f.out["powershell list"] = winRoster
	f.out["powershell add"] = ""
	g := winGroup(f)
	ctx := context.Background()

	out, err := g.Add(ctx, Request{Member: "alice", Source: "local"})
	if err != nil || out.State != StateAlready {
		t.Fatalf("local alice: %+v %v", out, err)
	}
	// CONTOSO\alice is not local alice
	out, err = g.Add(ctx, Request{Member: `CONTOSO\alice`, Source: "domain"})
	if err != nil || out.State != StateAdded || out.Member != `CONTOSO\alice` {
		t.Fatalf("domain alice: %+v %v", out, err)
	}
	// an Entra name without a domain becomes AzureAD\name, passed by env
	out, err = g.Add(ctx, Request{Member: "bob@contoso.com", Source: "entra"})
	if err != nil || out.Member != `AzureAD\bob@contoso.com` {
		t.Fatalf("entra: %+v %v", out, err)
	}
	last := f.envs[len(f.envs)-1]
	if len(last) != 1 || last[0] != `SG_TARGET=AzureAD\bob@contoso.com` {
		t.Fatalf("env %v", last)
	}
	// a group that can't be listed doesn't stop an add (as the script)
	f2 := newFake()
	f2.out["powershell add"] = ""
	if out, err := winGroup(f2).Add(ctx, Request{SID: "S-1-5-21-1-2-3-1009"}); err != nil || out.State != StateAdded {
		t.Fatalf("unlisted: %+v %v", out, err)
	}
}

func TestWindows_RemoveGuards(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	f.out["powershell list"] = winRoster
	f.out["powershell remove"] = ""
	g := winGroup(f)

	if _, err := g.Remove(ctx, Request{SID: "S-1-5-21-1-2-3-500"}); !errors.Is(err, ErrBuiltinAdmin) {
		t.Errorf("RID 500: %v", err)
	}
	if out, err := g.Remove(ctx, Request{Member: "nobody"}); err != nil || out.State != StateAbsent {
		t.Errorf("absent: %+v %v", out, err)
	}
	out, err := g.Remove(ctx, Request{Member: "alice", SignOut: true})
	if err != nil || out.State != StateRemoved || out.SignedOut == nil || *out.SignedOut != 2 || !f.called("signout alice") {
		t.Fatalf("remove alice: %+v %v %v", out, err, f.calls)
	}
	if env := f.envs[len(f.envs)-1]; len(env) != 1 || env[0] != "SG_SID=S-1-5-21-1-2-3-1001" {
		t.Fatalf("remove env %v", env)
	}

	// only it and a disabled built-in Administrator and a group are left:
	// it is the last enabled administrator
	f2 := newFake()
	f2.out["powershell list"] = `[{"name":"PC\\Administrator","sid":"S-1-5-21-1-2-3-500","source":"Local","class":"User","enabled":true},
{"name":"PC\\it","sid":"S-1-5-21-1-2-3-1000","source":"Local","class":"User","enabled":true},
{"name":"PC\\old","sid":"S-1-5-21-1-2-3-1002","source":"Local","class":"User","enabled":false},
{"name":"CONTOSO\\Domain Admins","sid":"S-1-5-21-9-9-9-512","source":"ActiveDirectory","class":"Group","enabled":true}]`
	if _, err := winGroup(f2).Remove(ctx, Request{Member: "it"}); err == nil || !strings.Contains(err.Error(), "last administrator") {
		t.Errorf("last admin: %v", err)
	}
	if f2.called("powershell remove") {
		t.Error("removed the last administrator")
	}
	// a directory user counts as enabled
	f2.out["powershell list"] = strings.Replace(f2.out["powershell list"], `"class":"Group"`, `"class":"User"`, 1)
	f2.out["powershell remove"] = ""
	if _, err := winGroup(f2).Remove(ctx, Request{Member: "it"}); err != nil {
		t.Errorf("with a directory admin: %v", err)
	}

	f3 := newFake()
	f3.out["powershell list"] = `[{"name":"NT AUTHORITY\\SYSTEM","sid":"S-1-5-18","source":"Local","class":"User","enabled":true},{"name":"PC\\it","sid":"S-1-5-21-1-2-3-1000","source":"Local","class":"User","enabled":true}]`
	if _, err := winGroup(f3).Remove(ctx, Request{SID: "S-1-5-18"}); !errors.Is(err, ErrSystemAccount) {
		t.Errorf("SYSTEM: %v", err)
	}
	// a single member is returned as one object by older PowerShell; the
	// script wraps it in an array, but an unlistable group is an error
	f4 := newFake()
	if _, err := winGroup(f4).Remove(ctx, Request{Member: "it"}); err == nil {
		t.Error("remove with an unlistable group succeeded")
	}
}

// ── macOS ────────────────────────────────────────────────────────────────────

func TestDarwin(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	f.out["id alice"] = "uid=501(alice)"
	f.out["dseditgroup -o edit -a alice -t user admin"] = ""
	g := &darwinGroup{run: f.run, self: "root"}
	// not a member until added
	added := false
	g.run = func(ctx context.Context, tool string, args []string, env []string) (string, error) {
		line := tool + " " + strings.Join(args, " ")
		if line == "dseditgroup -o checkmember -m alice admin" {
			if added {
				return "yes alice is a member", nil
			}
			return "", &ExitError{Tool: tool, Code: 67}
		}
		if line == "dseditgroup -o edit -a alice -t user admin" {
			added = true
		}
		return f.run(ctx, tool, args, env)
	}
	out, err := g.Add(ctx, Request{Member: `MAC\alice`})
	if err != nil || out.State != StateAdded || out.Member != "alice" {
		t.Fatalf("add: %+v %v", out, err)
	}
	if out, _ := g.Add(ctx, Request{Member: "alice"}); out.State != StateAlready {
		t.Fatalf("already: %+v", out)
	}
	if _, err := g.Add(ctx, Request{Member: "ghost"}); err == nil || !strings.Contains(err.Error(), "no account") {
		t.Fatalf("ghost: %v", err)
	}

	if _, err := g.Remove(ctx, Request{Member: "root"}); !errors.Is(err, ErrRoot) {
		t.Errorf("root: %v", err)
	}
	g.self = "svc"
	if _, err := g.Remove(ctx, Request{Member: "svc"}); !errors.Is(err, ErrOwnAccount) {
		t.Errorf("own: %v", err)
	}
	f.out["dscl . -read /Groups/admin GroupMembership"] = "GroupMembership: root alice"
	if _, err := g.Remove(ctx, Request{Member: "alice"}); err == nil || !strings.Contains(err.Error(), "last administrator") {
		t.Errorf("last: %v", err)
	}
	f.out["dscl . -read /Groups/admin GroupMembership"] = "GroupMembership: root alice it"
	f.out["dseditgroup -o edit -d alice -t user admin"] = ""
	f.out["id -u alice"] = "501\n"
	f.out["launchctl bootout gui/501"] = ""
	out, err = g.Remove(ctx, Request{Member: "alice", SignOut: true})
	if err != nil || out.State != StateRemoved || *out.SignedOut != 1 {
		t.Fatalf("remove: %+v %v", out, err)
	}
	added = false
	if out, _ := g.Remove(ctx, Request{Member: "alice"}); out.State != StateAbsent {
		t.Fatalf("absent: %+v", out)
	}
}

// ── Linux ────────────────────────────────────────────────────────────────────

func TestLinux_Add(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	f.out["id alice"] = "uid=1001(alice)"
	f.out["getent group wheel"] = "wheel:x:10:it"
	f.out["id -nG alice"] = "alice users"
	f.out["gpasswd -a alice wheel"] = ""
	g := &linuxGroup{run: f.run}
	out, err := g.Add(ctx, Request{Member: "alice"})
	if err != nil || out.State != StateAdded || out.Group != "wheel" {
		t.Fatalf("%+v %v", out, err)
	}
	f.out["getent group sudo"] = "sudo:x:27:alice,it"
	out, err = g.Add(ctx, Request{Member: "alice"})
	if err != nil || out.State != StateAlready || out.Group != "sudo" {
		t.Fatalf("already: %+v %v", out, err)
	}
	f2 := newFake()
	f2.out["id alice"] = "x"
	if _, err := (&linuxGroup{run: f2.run}).Add(ctx, Request{Member: "alice"}); err == nil {
		t.Fatal("no sudo or wheel: accepted")
	}
}

func TestLinux_Remove(t *testing.T) {
	ctx := context.Background()
	f := newFake()
	f.out["getent group sudo"] = "sudo:x:27:alice,it"
	f.out["getent group admin"] = "admin:x:110:alice"
	f.out["gpasswd -d alice sudo"] = ""
	f.out["gpasswd -d alice admin"] = ""
	f.out["loginctl terminate-user alice"] = ""
	g := &linuxGroup{run: f.run}
	out, err := g.Remove(ctx, Request{Member: "alice", SignOut: true})
	if err != nil || out.State != StateRemoved || *out.SignedOut != 1 || !f.called("gpasswd -d alice admin") {
		t.Fatalf("%+v %v %v", out, err, f.calls)
	}
	f.out["getent group sudo"] = "sudo:x:27:alice,root"
	if _, err := g.Remove(ctx, Request{Member: "alice"}); err == nil || !strings.Contains(err.Error(), "last administrator") {
		t.Fatalf("last: %v", err)
	}
	if _, err := g.Remove(ctx, Request{Member: "root"}); !errors.Is(err, ErrRoot) {
		t.Fatalf("root: %v", err)
	}
	if out, _ := g.Remove(ctx, Request{Member: "bob"}); out.State != StateAbsent {
		t.Fatalf("absent: %+v", out)
	}
	if _, err := g.Remove(ctx, Request{Member: "--help"}); !errors.Is(err, ErrBadName) {
		t.Fatalf("flag name: %v", err)
	}
}

func TestForOS(t *testing.T) {
	for _, goos := range []string{"windows", "darwin", "linux"} {
		if g, err := ForOS(goos, newFake().run); err != nil || g == nil {
			t.Errorf("%s: %v", goos, err)
		}
	}
	if _, err := ForOS("plan9", newFake().run); err == nil {
		t.Error("plan9 supported")
	}
}
