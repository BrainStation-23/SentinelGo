package scanworker

// Windows workers (#328). The service starts each worker sandboxed:
//
//   - in an AppContainer with no capabilities: no network at all (loopback
//     included), and no file, registry or object access beyond what is
//     granted to app packages (system files) or to this container (the
//     worker's own executable);
//   - a restricted copy of the service's token: every privilege removed,
//     Administrators deny-only, and (level 0) restricting SIDs Everyone,
//     Users, Authenticated Users and RESTRICTED, so the worker can open only
//     what any user may (system files, not users' profiles);
//   - low integrity, so it can't write to normal locations;
//   - a Job object: one process (no children), a memory limit, killed when
//     the service's handle closes, and no UI.
//
// A worker that can't start at the strictest level drops to the next: level
// 0 is all of the above; level 1 the same without the AppContainer (an older
// Windows, or an executable whose ACL can't be changed); level 2 also
// without restricting SIDs (an install directory Users can't read, say).
// The level reached is reported in Health.Sandbox.
//
// The file goes to the worker as a read-only handle duplicated into its
// process: it never opens a path.

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Sandbox levels.
const (
	levelAppContainer = iota // AppContainer, restricted token, low integrity, job
	levelRestricted          // restricted token, low integrity, job
	levelLowIL               // low integrity, job
	levelCount
)

const (
	workerMemoryLimit = 1 << 30
	// fileGenericRead is FILE_GENERIC_READ: the only access the worker gets.
	fileGenericRead = 0x00120089
	// fileGenericExecuteRead is FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, how
	// a read-and-execute entry is stored once mapped.
	fileGenericExecuteRead = 0x001200a9
	// disableMaxPrivilege is CreateRestrictedToken's DISABLE_MAX_PRIVILEGE.
	disableMaxPrivilege = 0x1
	jobUILimitAll       = 0xFF // every JOB_OBJECT_UILIMIT_* flag
	// appContainerName names the workers' AppContainer; its SID is derived
	// from the name, so it is the same on every start.
	appContainerName = "SentinelGo.DLP.ScanWorker"
	// attrSecurityCapabilities is PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES.
	attrSecurityCapabilities = 0x00020009
	// exeAccess is what the container needs on the worker's executable.
	exeAccess = windows.GENERIC_READ | windows.GENERIC_EXECUTE
)

var (
	procCreateRestrictedToken     = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")
	userenv                       = windows.NewLazySystemDLL("userenv.dll")
	procCreateAppContainerProfile = userenv.NewProc("CreateAppContainerProfile")
	procDeriveAppContainerSid     = userenv.NewProc("DeriveAppContainerSidFromAppContainerName")
)

// hresultAlreadyExists is HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS).
const hresultAlreadyExists = 0x800700b7

// securityCapabilities is SECURITY_CAPABILITIES: the AppContainer a process
// starts in and its capabilities (none: no network, no libraries).
type securityCapabilities struct {
	AppContainerSid *windows.SID
	Capabilities    *windows.SIDAndAttributes
	CapabilityCount uint32
	Reserved        uint32
}

// poolOS keeps the sandbox level workers start at: it drops a level when a
// worker can't start at the stricter one, and stays there. The AppContainer
// is set up once per pool.
type poolOS struct {
	level   int
	acOnce  sync.Once
	acSID   *windows.SID
	acError error
}

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
	var caps *securityCapabilities
	if level == levelAppContainer {
		sid, err := p.appContainer()
		if err != nil {
			return nil, "", fmt.Errorf("AppContainer: %w", err)
		}
		caps = &securityCapabilities{AppContainerSid: sid}
	}
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

	pi, job, err := p.startSuspended(token, caps, inR, outW)
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

// startSuspended creates the worker suspended (in caps' AppContainer when
// caps isn't nil), puts it in its job, then lets it run; it inherits only
// stdin and stdout.
func (p *Pool) startSuspended(token windows.Token, caps *securityCapabilities, stdin, stdout windows.Handle) (windows.ProcessInformation, windows.Handle, error) {
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
	vars := []string{"SystemRoot=" + root}
	if caps != nil {
		// Windows points the container's TEMP and LOCALAPPDATA at its own
		// folder in the profile, and fails to start it without these.
		for _, k := range []string{"USERPROFILE", "LOCALAPPDATA"} {
			if v := os.Getenv(k); v != "" {
				vars = append(vars, k+"="+v)
			}
		}
	}
	env := envBlock(append(vars, p.opts.Env...))

	inherit := []windows.Handle{stdin, stdout}
	attrs, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return pi, 0, err
	}
	defer attrs.Delete()
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&inherit[0]), uintptr(len(inherit))*unsafe.Sizeof(inherit[0])); err != nil { // #nosec G103 -- the handle list the attribute takes
		return pi, 0, err
	}
	if caps != nil {
		if err := attrs.Update(attrSecurityCapabilities, unsafe.Pointer(caps), unsafe.Sizeof(*caps)); err != nil { // #nosec G103 -- SECURITY_CAPABILITIES for the attribute
			return pi, 0, err
		}
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

// appContainer returns the workers' AppContainer SID, once it can run the
// worker's executable.
func (p *Pool) appContainer() (*windows.SID, error) {
	p.osState.acOnce.Do(func() {
		sid, err := appContainerSID(appContainerName)
		if err == nil {
			err = grantAccess(p.opts.Exe, sid, exeAccess)
		}
		p.osState.acSID, p.osState.acError = sid, err
	})
	return p.osState.acSID, p.osState.acError
}

// appContainerSID creates the AppContainer's profile if it doesn't exist
// yet (Windows needs it to start a process in the container) and returns
// its SID.
func appContainerSID(name string) (*windows.SID, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	if err := procCreateAppContainerProfile.Find(); err != nil {
		return nil, err // before Windows 8
	}
	var sid *windows.SID
	hr, _, _ := procCreateAppContainerProfile.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(n)), // #nosec G103 -- name, display name, description
		0, 0, uintptr(unsafe.Pointer(&sid))) // #nosec G103 -- out-parameter
	if uint32(hr) == hresultAlreadyExists { // #nosec G115 -- an HRESULT
		hr, _, _ = procDeriveAppContainerSid.Call(uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(&sid))) // #nosec G103 -- in and out parameters
	}
	if hr != 0 {
		return nil, fmt.Errorf("AppContainer profile: HRESULT %#x", hr)
	}
	defer func() { _ = windows.FreeSid(sid) }()
	return sid.Copy()
}

// grantAccess makes sure the file's DACL grants sid this access, adding an
// entry only when one is missing (so the file isn't rewritten each start).
func grantAccess(path string, sid *windows.SID, access windows.ACCESS_MASK) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if aclGrants(dacl, sid, access) {
		return nil
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: access, AccessMode: windows.GRANT_ACCESS, Inheritance: windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid)},
	}}, dacl)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// aclGrants reports whether an allow entry for sid in acl holds all of
// access (generic rights as they are stored, before mapping).
func aclGrants(acl *windows.ACL, sid *windows.SID, access windows.ACCESS_MASK) bool {
	if acl == nil {
		return true // a NULL DACL grants everything
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) // #nosec G103 -- the SID follows the ACE header
		if aceSID.Equals(sid) && (ace.Mask&access == access || ace.Mask&fileGenericExecuteRead == fileGenericExecuteRead) {
			return true
		}
	}
	return false
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
	if level <= levelRestricted {
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
	if level <= levelRestricted {
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
// the user, SYSTEM and RESTRICTED get full access, and app packages too (an
// AppContainer's access check needs an entry for its package). Without it
// the Go runtime can't open its own threads and the worker dies at start.
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
	packages, err := windows.CreateWellKnownSid(windows.WinBuiltinAnyPackageSid)
	if err != nil {
		return err
	}
	var entries []windows.EXPLICIT_ACCESS
	for _, sid := range []*windows.SID{user.User.Sid, system, restricted, packages} {
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
