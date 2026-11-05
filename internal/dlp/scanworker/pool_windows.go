package scanworker

// Windows workers (#328). The service starts each worker sandboxed:
//
//   - a restricted copy of the service's token: every privilege removed,
//     Administrators deny-only, and (level 0) restricting SIDs Everyone,
//     Users, Authenticated Users and RESTRICTED, so the worker can open only
//     what any user may (system files, not users' profiles);
//   - low integrity, so it can't write to normal locations;
//   - a Job object: one process (no children), a memory limit, killed when
//     the service's handle closes, and no UI.
//
// A worker that can't start at level 0 (an install directory Users can't
// read, say) is started at level 1: the same without restricting SIDs. The
// level reached is reported in Health.Sandbox.
//
// The file goes to the worker as a read-only handle duplicated into its
// process: it never opens a path.

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Sandbox levels.
const (
	levelRestricted = iota // restricted token, low integrity, job
	levelLowIL             // low integrity, job
	levelCount
)

const (
	workerMemoryLimit = 1 << 30
	// fileGenericRead is FILE_GENERIC_READ: the only access the worker gets.
	fileGenericRead = 0x00120089
	// disableMaxPrivilege is CreateRestrictedToken's DISABLE_MAX_PRIVILEGE.
	disableMaxPrivilege = 0x1
	jobUILimitAll       = 0xFF // every JOB_OBJECT_UILIMIT_* flag
)

var procCreateRestrictedToken = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")

// poolOS keeps the sandbox level workers start at: it drops a level when a
// worker can't start at the stricter one, and stays there.
type poolOS struct{ level int }

// workerProc is a Windows worker's process and its job.
type workerProc struct {
	process windows.Handle
	job     windows.Handle
}

// spawn starts a worker at the pool's level, dropping to the next level when
// one can't start; the level that worked is kept for later workers.
func (p *Pool) spawn() (*worker, error) {
	p.mu.Lock()
	level := p.osState.level
	p.mu.Unlock()
	var lastErr error
	for ; level < levelCount; level++ {
		w, desc, err := p.spawnAt(level)
		if err != nil {
			lastErr = err
			continue
		}
		p.mu.Lock()
		p.osState.level = level
		p.all[w] = struct{}{}
		p.sandbox = desc + ",job"
		p.mu.Unlock()
		return w, nil
	}
	return nil, lastErr
}

func (p *Pool) spawnAt(level int) (*worker, string, error) {
	token, err := sandboxToken(level)
	if err != nil {
		return nil, "", fmt.Errorf("sandbox token: %w", err)
	}
	defer func() { _ = token.Close() }()

	// The worker's stdin and stdout; only its own ends are inheritable.
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	var inR, inW, outR, outW windows.Handle
	if err := windows.CreatePipe(&inR, &inW, sa, 0); err != nil {
		return nil, "", err
	}
	if err := windows.CreatePipe(&outR, &outW, sa, 0); err != nil {
		closeHandles(inR, inW)
		return nil, "", err
	}
	_ = windows.SetHandleInformation(inW, windows.HANDLE_FLAG_INHERIT, 0)
	_ = windows.SetHandleInformation(outR, windows.HANDLE_FLAG_INHERIT, 0)

	pi, job, err := p.startSuspended(token, inR, outW)
	closeHandles(inR, outW) // the worker has its own copies
	if err != nil {
		closeHandles(inW, outR)
		return nil, "", err
	}
	w := &worker{
		c:      newPipeConn(os.NewFile(uintptr(outR), "scan-worker-out"), os.NewFile(uintptr(inW), "scan-worker-in"), false),
		proc:   workerProc{process: pi.Process, job: job},
		exited: make(chan struct{}),
	}
	go func() {
		_, _ = windows.WaitForSingleObject(pi.Process, windows.INFINITE)
		close(w.exited)
	}()
	desc, err := awaitReady(w)
	if err != nil {
		return nil, "", err
	}
	return w, desc, nil
}

// startSuspended creates the worker suspended, puts it in its job, then
// lets it run; it inherits only stdin and stdout.
func (p *Pool) startSuspended(token windows.Token, stdin, stdout windows.Handle) (windows.ProcessInformation, windows.Handle, error) {
	var pi windows.ProcessInformation
	exe, err := windows.UTF16PtrFromString(p.opts.Exe)
	if err != nil {
		return pi, 0, err
	}
	args := []string{syscall.EscapeArg(p.opts.Exe)}
	for _, a := range p.opts.Args {
		args = append(args, syscall.EscapeArg(a))
	}
	cmdline, err := windows.UTF16PtrFromString(strings.Join(args, " "))
	if err != nil {
		return pi, 0, err
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	dir, err := windows.UTF16PtrFromString(root)
	if err != nil {
		return pi, 0, err
	}
	env := envBlock(append([]string{"SystemRoot=" + root}, p.opts.Env...))

	inherit := []windows.Handle{stdin, stdout}
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return pi, 0, err
	}
	defer attrs.Delete()
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&inherit[0]), uintptr(len(inherit))*unsafe.Sizeof(inherit[0])); err != nil { // #nosec G103 -- the handle list the attribute takes
		return pi, 0, err
	}
	si := windows.StartupInfoEx{
		StartupInfo: windows.StartupInfo{
			Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})), Flags: windows.STARTF_USESTDHANDLES,
			StdInput: stdin, StdOutput: stdout,
		},
		ProcThreadAttributeList: attrs.List(),
	}
	flags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW | windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_UNICODE_ENVIRONMENT)
	if err := windows.CreateProcessAsUser(token, exe, cmdline, nil, nil, true, flags, &env[0], dir, &si.StartupInfo, &pi); err != nil {
		return pi, 0, fmt.Errorf("start scan worker: %w", err)
	}
	defer func() { _ = windows.CloseHandle(pi.Thread) }()
	abort := func() {
		_ = windows.TerminateProcess(pi.Process, 1)
		_ = windows.CloseHandle(pi.Process)
	}
	job, err := newWorkerJob()
	if err != nil {
		abort()
		return pi, 0, err
	}
	if err := windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		abort()
		_ = windows.CloseHandle(job)
		return pi, 0, fmt.Errorf("assign scan worker to its job: %w", err)
	}
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		abort()
		_ = windows.CloseHandle(job)
		return pi, 0, fmt.Errorf("resume scan worker: %w", err)
	}
	return pi, job, nil
}

// envBlock is a Unicode environment block: NUL-separated, double NUL end.
func envBlock(vars []string) []uint16 {
	var b []uint16
	for _, v := range vars {
		if strings.ContainsRune(v, 0) {
			continue
		}
		b = append(b, windows.StringToUTF16(v)...) // includes the NUL
	}
	return append(b, 0)
}

// sandboxToken makes the worker's primary token from the service's.
func sandboxToken(level int) (windows.Token, error) {
	var self windows.Token
	access := uint32(windows.TOKEN_DUPLICATE | windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_QUERY | windows.TOKEN_ADJUST_DEFAULT)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), access, &self); err != nil {
		return 0, err
	}
	defer func() { _ = self.Close() }()

	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return 0, err
	}
	disable := []windows.SIDAndAttributes{{Sid: admins}}
	var restrict []windows.SIDAndAttributes
	if level == levelRestricted {
		for _, k := range []windows.WELL_KNOWN_SID_TYPE{windows.WinWorldSid, windows.WinBuiltinUsersSid,
			windows.WinAuthenticatedUserSid, windows.WinRestrictedCodeSid} {
			sid, err := windows.CreateWellKnownSid(k)
			if err != nil {
				return 0, err
			}
			restrict = append(restrict, windows.SIDAndAttributes{Sid: sid})
		}
	}
	var restrictPtr *windows.SIDAndAttributes
	if len(restrict) > 0 {
		restrictPtr = &restrict[0]
	}
	var tok windows.Token
	r, _, callErr := procCreateRestrictedToken.Call(uintptr(self), disableMaxPrivilege,
		uintptr(len(disable)), uintptr(unsafe.Pointer(&disable[0])), // #nosec G103 -- SID_AND_ATTRIBUTES array for the API
		0, 0,
		uintptr(len(restrict)), uintptr(unsafe.Pointer(restrictPtr)), // #nosec G103 -- as above
		uintptr(unsafe.Pointer(&tok))) // #nosec G103 -- out-parameter
	if r == 0 {
		return 0, fmt.Errorf("CreateRestrictedToken: %w", callErr)
	}
	if level == levelRestricted {
		if err := setDefaultDACL(self, tok); err != nil {
			_ = tok.Close()
			return 0, fmt.Errorf("default DACL: %w", err)
		}
	}
	low, err := windows.CreateWellKnownSid(windows.WinLowLabelSid)
	if err != nil {
		_ = tok.Close()
		return 0, err
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: low, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err := windows.SetTokenInformation(tok, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&label)), // #nosec G103 -- TOKEN_MANDATORY_LABEL for the API
		uint32(unsafe.Sizeof(label))+uint32(low.Len())); err != nil { // #nosec G115 -- a SID is at most 68 bytes
		_ = tok.Close()
		return 0, fmt.Errorf("low integrity: %w", err)
	}
	return tok, nil
}

// tokenDefaultDACL is TOKEN_DEFAULT_DACL.
type tokenDefaultDACL struct{ DefaultDacl *windows.ACL }

// setDefaultDACL gives the objects the worker creates (its own process and
// threads among them) a DACL that passes the restricted access check too:
// the user, SYSTEM and RESTRICTED get full access. Without it the Go runtime
// can't open its own threads and the worker dies at start.
func setDefaultDACL(self, tok windows.Token) error {
	user, err := self.GetTokenUser()
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	restricted, err := windows.CreateWellKnownSid(windows.WinRestrictedCodeSid)
	if err != nil {
		return err
	}
	var entries []windows.EXPLICIT_ACCESS
	for _, sid := range []*windows.SID{user.User.Sid, system, restricted} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_UNKNOWN,
				TrusteeValue: windows.TrusteeValueFromSID(sid)},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return err
	}
	d := tokenDefaultDACL{DefaultDacl: acl}
	return windows.SetTokenInformation(tok, windows.TokenDefaultDacl, (*byte)(unsafe.Pointer(&d)), uint32(unsafe.Sizeof(d))) // #nosec G103 -- TOKEN_DEFAULT_DACL for the API
}

// newWorkerJob makes the job a worker runs in.
func newWorkerJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("create job object: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
		windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY | windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
	info.BasicLimitInformation.ActiveProcessLimit = 1
	info.ProcessMemoryLimit = workerMemoryLimit
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil { // #nosec G103 -- Win32 struct passed by pointer
		_ = windows.CloseHandle(job)
		return 0, fmt.Errorf("configure job object: %w", err)
	}
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: jobUILimitAll}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectBasicUIRestrictions,
		uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui))); err != nil { // #nosec G103 -- Win32 struct passed by pointer
		_ = windows.CloseHandle(job)
		return 0, fmt.Errorf("configure job UI limits: %w", err)
	}
	return job, nil
}

func closeHandles(hs ...windows.Handle) {
	for _, h := range hs {
		_ = windows.CloseHandle(h)
	}
}

// sendScan duplicates f into the worker as a read-only handle and sends the
// request naming it. The worker closes it after the scan; if it dies first,
// the handle goes with its process.
func (w *worker) sendScan(m message, f *os.File) error {
	var dup windows.Handle
	if err := windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(f.Fd()), w.proc.process, &dup,
		fileGenericRead, false, 0); err != nil {
		return fmt.Errorf("hand the file to the scan worker: %w", err)
	}
	m.Handle = uint64(dup)
	return w.c.writeMsg(m, -1)
}

func (w *worker) kill() {
	_ = w.c.close()
	_ = windows.TerminateProcess(w.proc.process, 1)
	select {
	case <-w.exited:
	case <-time.After(5 * time.Second):
		return // keep the handles: the waiter still uses the process handle
	}
	closeHandles(w.proc.process, w.proc.job)
}
