//go:build windows

package epm

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// LaunchResult identifies a process started by LaunchAsUser.
type LaunchResult struct {
	ProcessID uint32
	ThreadID  uint32
}

// LaunchAsUser starts appPath (with optional extra arguments in commandLine)
// as the user represented by primaryToken, in that user's session and default
// desktop, using envBlock for the child's environment. This is the sole
// enforcement primitive that actually grants privilege: callers must only
// reach it after Engine.Evaluate has already returned Allowed for the
// request.
//
// primaryToken must be a primary (not impersonation) token — see
// DuplicateAsPrimaryToken — obtained from the target session's user, and the
// caller (a Windows service running as LocalSystem) must hold
// SeAssignPrimaryTokenPrivilege and SeIncreaseQuotaPrivilege, both granted to
// LocalSystem by default.
func LaunchAsUser(primaryToken windows.Token, appPath, commandLine string, env *environmentBlock) (*LaunchResult, error) {
	appPathPtr, err := windows.UTF16PtrFromString(appPath)
	if err != nil {
		return nil, fmt.Errorf("convert app path: %w", err)
	}

	cmdLinePtr, err := windows.UTF16PtrFromString(buildCommandLine(appPath, commandLine))
	if err != nil {
		return nil, fmt.Errorf("convert command line: %w", err)
	}

	desktopPtr, err := windows.UTF16PtrFromString(`winsta0\default`)
	if err != nil {
		return nil, fmt.Errorf("convert desktop name: %w", err)
	}

	si := &windows.StartupInfo{
		Cb:      uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Desktop: desktopPtr,
	}
	pi := &windows.ProcessInformation{}

	var envPtr *uint16
	if env != nil {
		envPtr = env.ptr
	}

	const creationFlags = windows.CREATE_UNICODE_ENVIRONMENT | windows.CREATE_NEW_CONSOLE

	if err := windows.CreateProcessAsUser(
		primaryToken,
		appPathPtr,
		cmdLinePtr,
		nil, // process security attributes: default
		nil, // thread security attributes: default
		false,
		creationFlags,
		envPtr,
		nil, // current directory: inherit the service's
		si,
		pi,
	); err != nil {
		return nil, fmt.Errorf("CreateProcessAsUser: %w", err)
	}

	// Fire-and-forget: the launched process is now the user's own, running in
	// their session. We only need its identity for the audit record, not its
	// lifetime, so close both handles immediately.
	_ = windows.CloseHandle(pi.Thread)
	_ = windows.CloseHandle(pi.Process)

	return &LaunchResult{ProcessID: pi.ProcessId, ThreadID: pi.ThreadId}, nil
}

// buildCommandLine assembles a Win32 command line: the quoted application
// path followed by any additional arguments verbatim. CreateProcess requires
// lpCommandLine to include the module name by convention (argv[0]).
func buildCommandLine(appPath, extraArgs string) string {
	cmd := quoteWindowsArg(appPath)
	if extraArgs != "" {
		cmd += " " + extraArgs
	}
	return cmd
}

// quoteWindowsArg quotes s as a single Win32 command-line argument, following
// the same escaping rules CommandLineToArgvW uses to parse it back out
// (MSDN "Parsing C++ Command-Line Arguments"): a run of backslashes is only
// escaped (doubled) when it immediately precedes a double quote — including
// the closing quote this function adds — and literal double quotes are
// escaped with a backslash. Ordinary backslashes, such as path separators,
// are left untouched.
//
// fmt.Sprintf("%q", ...) is not this: it produces Go string-literal escaping
// (every backslash doubled), which is the wrong quoting convention for a
// Win32 command line and would corrupt any path containing backslashes.
func quoteWindowsArg(s string) string {
	var b strings.Builder
	b.WriteByte('"')

	backslashes := 0
	for _, r := range s {
		switch r {
		case '\\':
			backslashes++
			b.WriteByte('\\')
		case '"':
			for ; backslashes > 0; backslashes-- {
				b.WriteByte('\\')
			}
			b.WriteString(`\"`)
		default:
			backslashes = 0
			b.WriteRune(r)
		}
	}
	for ; backslashes > 0; backslashes-- {
		b.WriteByte('\\')
	}

	b.WriteByte('"')
	return b.String()
}
