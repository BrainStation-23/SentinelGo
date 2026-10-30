//go:build windows

package session

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"sentinelgo/internal/dlp/channel"
	"sentinelgo/internal/dlp/ipc"
)

// New returns the Windows supervisor: one `sentinelgo dlp-session` helper per
// active interactive session, launched as that session's user. Every helper
// is in a job object that kills it when the service exits, so a crash, a
// stop or a self-update (which needs the .exe unlocked) never leaves helpers
// running the old image.
func New(sink channel.EventSink) Service {
	l, err := newWinLauncher()
	if err != nil {
		log.Printf("DLP: helper launcher unavailable (%v); helpers must be started by hand", err)
		return &manualSupervisor{Hub: NewHub(ipc.DefaultAddress, sink)}
	}
	return newLaunchSupervisor(NewHub(ipc.DefaultAddress, sink), l)
}

type winLauncher struct {
	exe string
	job windows.Handle
}

func newWinLauncher() (*winLauncher, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("create job object: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil { // #nosec G103 -- Win32 struct passed by pointer
		_ = windows.CloseHandle(job)
		return nil, fmt.Errorf("configure job object: %w", err)
	}
	// The job handle stays open for the life of the service: closing it (the
	// process exiting) kills every helper.
	return &winLauncher{exe: exe, job: job}, nil
}

// Sessions lists active interactive sessions. Session 0 (services) never
// gets a helper; disconnected sessions (switched away from) don't either.
func (l *winLauncher) Sessions() ([]string, error) {
	var info *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &info, &count); err != nil {
		return nil, fmt.Errorf("WTSEnumerateSessions: %w", err)
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info))) // #nosec G103 -- frees the buffer WTSEnumerateSessions allocated
	var out []string
	for _, s := range unsafe.Slice(info, count) { // #nosec G103 -- count entries, as returned by WTSEnumerateSessions
		if s.SessionID != 0 && s.State == windows.WTSActive {
			out = append(out, strconv.FormatUint(uint64(s.SessionID), 10))
		}
	}
	return out, nil
}

// Start launches the helper in session as its user, on the interactive
// desktop, without a window, inside the job.
func (l *winLauncher) Start(session string) (Process, error) {
	id, err := strconv.ParseUint(session, 10, 32)
	if err != nil {
		return nil, err
	}
	var token windows.Token
	if err := windows.WTSQueryUserToken(uint32(id), &token); err != nil {
		return nil, fmt.Errorf("user token for session %s: %w", session, err)
	}
	defer func() { _ = token.Close() }()

	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, token, false); err != nil {
		return nil, fmt.Errorf("environment for session %s: %w", session, err)
	}
	defer func() { _ = windows.DestroyEnvironmentBlock(env) }()

	exe, err := windows.UTF16PtrFromString(l.exe)
	if err != nil {
		return nil, err
	}
	cmd, err := windows.UTF16PtrFromString(syscall.EscapeArg(l.exe) + " dlp-session")
	if err != nil {
		return nil, err
	}
	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: desktop}
	var pi windows.ProcessInformation
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NO_WINDOW | windows.CREATE_SUSPENDED)
	if err := windows.CreateProcessAsUser(token, exe, cmd, nil, nil, false, flags, env, nil, &si, &pi); err != nil {
		return nil, fmt.Errorf("start helper in session %s: %w", session, err)
	}
	defer func() { _ = windows.CloseHandle(pi.Thread) }()

	// Into the job before it runs, so it can't outlive the service.
	if err := windows.AssignProcessToJobObject(l.job, pi.Process); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		_ = windows.CloseHandle(pi.Process)
		return nil, fmt.Errorf("assign helper to job: %w", err)
	}
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		_ = windows.CloseHandle(pi.Process)
		return nil, fmt.Errorf("resume helper: %w", err)
	}
	log.Printf("DLP: started helper in session %s (pid %d)", session, pi.ProcessId)
	return &winProcess{h: pi.Process}, nil
}

// winProcess owns the helper's process handle. Kill after the handle is
// closed is a no-op (a closed handle value can be reused by another object).
type winProcess struct {
	h      windows.Handle
	mu     sync.Mutex
	closed bool
}

func (p *winProcess) Wait() error {
	_, err := windows.WaitForSingleObject(p.h, windows.INFINITE)
	p.mu.Lock()
	p.closed = true
	_ = windows.CloseHandle(p.h)
	p.mu.Unlock()
	return err
}

func (p *winProcess) Kill() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	return windows.TerminateProcess(p.h, 1)
}

// CleanupHelpers has nothing to remove on Windows: helpers live in the
// service's job object and end with it.
func CleanupHelpers() error { return nil }
