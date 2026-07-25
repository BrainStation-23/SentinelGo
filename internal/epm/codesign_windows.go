//go:build windows

package epm

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// modCrypt32 and procCryptMsgClose exist because golang.org/x/sys/windows
// does not wrap CryptMsgClose. This is a plain syscall through a lazy DLL
// proc handle — the same pattern already used for wevtapi.dll in
// internal/auditlogs/collector/collector_windows.go — not cgo, and it keeps
// the binary a static, dependency-free, cross-compilable artifact per
// CLAUDE.md's no-cgo rule.
var (
	modCrypt32        = windows.NewLazySystemDLL("crypt32.dll")
	procCryptMsgClose = modCrypt32.NewProc("CryptMsgClose")
)

func cryptMsgClose(msg windows.Handle) {
	_, _, _ = procCryptMsgClose.Call(uintptr(msg))
}

// VerifyAuthenticode checks path's Authenticode signature via the WinTrust
// API and, if the signature verifies, returns the signer's display name for
// use as ElevationRequest.Publisher (publisher-based policy matching).
//
// An error return means the file is unsigned or its signature does not
// verify; callers should treat that as "no publisher identity available"
// rather than aborting the whole elevation request outright — hash-based or
// path-based rules can still match an unsigned file.
func VerifyAuthenticode(path string) (publisher string, err error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", fmt.Errorf("convert path: %w", err)
	}

	fileInfo := &windows.WinTrustFileInfo{
		Size:     uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})),
		FilePath: pathPtr,
	}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fileInfo),
	}

	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)

	// Always release the verification state, even on failure.
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)

	if verifyErr != nil {
		return "", fmt.Errorf("authenticode verification failed: %w", verifyErr)
	}

	name, nameErr := signerDisplayName(path)
	if nameErr != nil {
		// The signature verified, but we couldn't extract a display name for
		// it. Report success with no name rather than failing the whole
		// check: the caller still knows the file is genuinely signed.
		return "", nil
	}
	return name, nil
}

// signerDisplayName extracts the simple display name of the signing
// (leaf/end-entity) certificate embedded in path's Authenticode signature,
// distinguishing it from any intermediate/root CA certificates embedded
// alongside it in the same PKCS#7 signature.
func signerDisplayName(path string) (string, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", fmt.Errorf("convert path: %w", err)
	}

	var encoding, contentType, formatType uint32
	var certStore, msg windows.Handle
	err = windows.CryptQueryObject(
		windows.CERT_QUERY_OBJECT_FILE,
		unsafe.Pointer(pathPtr),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		windows.CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		&encoding,
		&contentType,
		&formatType,
		&certStore,
		&msg,
		nil,
	)
	if err != nil {
		return "", fmt.Errorf("CryptQueryObject: %w", err)
	}
	defer func() { _ = windows.CertCloseStore(certStore, 0) }()
	defer cryptMsgClose(msg)

	return leafCertificateName(certStore)
}

// leafCertificateName picks the leaf (end-entity signing) certificate out of
// every certificate embedded in an Authenticode signature — which typically
// also includes the intermediate and root CA certificates that chain up to
// it — and returns its display name.
//
// golang.org/x/sys/windows does not wrap CryptMsgGetParam, so the exact
// signer cannot be identified via CMSG_SIGNER_INFO (its issuer + serial
// number) without hand-rolling that struct's layout and parsing it via a raw
// syscall — a meaningfully higher-risk change (wrong field offsets/alignment
// in a security-sensitive parsing path) with no real multi-certificate-signed
// binary available in this environment to validate it against. Instead, this
// uses a property of certificate chains that's checkable entirely through
// already-wrapped, well-tested APIs: the leaf certificate's Subject never
// equals any other certificate's Issuer within the same chain (nothing in a
// standard Authenticode signature is issued BY the end-entity certificate),
// whereas every intermediate/root CA certificate does appear as some other
// certificate's Issuer. Enumerating the embedded set and excluding anything
// that appears as an Issuer correctly isolates the leaf for the standard
// single-chain case (no cross-signing), which covers the overwhelming
// majority of real-world Authenticode signatures.
func leafCertificateName(certStore windows.Handle) (string, error) {
	type certNames struct{ subject, issuer string }
	var entries []certNames
	issuers := make(map[string]bool)

	// CertEnumCertificatesInStore frees the certificate context passed in as
	// prevContext on every call (including the initial nil), so cert is only
	// ever "ours" to free for the one iteration between assignment and the
	// next call. The final non-nil context is never passed to another call
	// (the loop exits instead), so it alone must be freed explicitly after
	// the loop.
	var cert *windows.CertContext
	for {
		next, err := windows.CertEnumCertificatesInStore(certStore, cert)
		if err != nil || next == nil {
			break
		}
		cert = next

		subject := certDisplayName(cert, 0)
		issuer := certDisplayName(cert, windows.CERT_NAME_ISSUER_FLAG)
		entries = append(entries, certNames{subject: subject, issuer: issuer})
		if issuer != "" {
			issuers[issuer] = true
		}
	}
	if cert != nil {
		_ = windows.CertFreeCertificateContext(cert)
	}

	if len(entries) == 0 {
		return "", fmt.Errorf("no certificates found in signature")
	}

	for _, e := range entries {
		if e.subject != "" && !issuers[e.subject] {
			return e.subject, nil
		}
	}

	// Fallback (e.g. a single self-signed certificate, where Subject equals
	// Issuer for the only entry, so the loop above finds no non-issuer
	// candidate): use the first certificate found, matching the simpler
	// behavior this function replaces.
	if entries[0].subject != "" {
		return entries[0].subject, nil
	}
	return "", fmt.Errorf("could not determine a certificate display name")
}

// certDisplayName returns cert's simple display name; flags may be 0 (Subject)
// or CERT_NAME_ISSUER_FLAG (Issuer). Returns "" if unavailable.
func certDisplayName(cert *windows.CertContext, flags uint32) string {
	var nameBuf [256]uint16
	chars := windows.CertGetNameString(cert, windows.CERT_NAME_SIMPLE_DISPLAY_TYPE, flags, nil, &nameBuf[0], uint32(len(nameBuf)))
	if chars <= 1 {
		return ""
	}
	// chars includes the trailing NUL; trim it for the Go string.
	return windows.UTF16ToString(nameBuf[:chars-1])
}
