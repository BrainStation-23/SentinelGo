package scanworker

import (
	"errors"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Serve is `sentinelgo dlp-scan` on Windows. The service starts the worker
// already sandboxed (pool_windows.go): an AppContainer and a restricted,
// low-integrity token in a Job object. The worker checks it really is low integrity and refuses to
// run otherwise, then serves scans on stdin/stdout. It never opens a path:
// files arrive as handles.
func Serve() error {
	desc, err := checkSandbox()
	if err != nil {
		return err
	}
	return serve(newPipeConn(os.Stdin, os.Stdout, true), desc)
}

const (
	// lowIntegrityRID is SECURITY_MANDATORY_LOW_RID.
	lowIntegrityRID = 0x1000
	// tokenIsAppContainer is the TokenIsAppContainer information class.
	tokenIsAppContainer = 29
)

var procIsTokenRestricted = windows.NewLazySystemDLL("advapi32.dll").NewProc("IsTokenRestricted")

// checkSandbox describes this process's token, and fails unless it runs at
// low integrity or below.
func checkSandbox() (string, error) {
	tok := windows.GetCurrentProcessToken()
	var n uint32
	_ = windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, nil, 0, &n)
	if n == 0 {
		return "", errors.New("can't read the token's integrity level")
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &buf[0], n, &n); err != nil {
		return "", err
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0])) // #nosec G103 -- TOKEN_MANDATORY_LABEL returned by the API
	sid := label.Label.Sid
	count := sid.SubAuthorityCount()
	if count == 0 || sid.SubAuthority(uint32(count-1)) > lowIntegrityRID {
		return "", errors.New("refusing to scan outside the sandbox: not low integrity")
	}
	parts := []string{"low_integrity"}
	var isAC uint32
	if err := windows.GetTokenInformation(tok, tokenIsAppContainer, (*byte)(unsafe.Pointer(&isAC)), 4, &n); err == nil && isAC != 0 { // #nosec G103 -- a DWORD out-parameter
		parts = append([]string{"appcontainer"}, parts...)
	}
	if r, _, _ := procIsTokenRestricted.Call(uintptr(tok)); r != 0 {
		parts = append(parts, "restricted_token")
	}
	return strings.Join(parts, ","), nil
}
