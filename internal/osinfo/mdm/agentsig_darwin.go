package mdm

// Reads the running agent's code signature through Security.framework
// (purego, no cgo): SecCodeCopySelf → SecCodeCopySigningInformation for the
// identifier, flags and team ID; SecCodeCopyDesignatedRequirement →
// SecRequirementCopyString for the designated requirement (the same text as
// `codesign -d -r-`); SecCodeCheckValidity against the Developer ID
// requirement to tell a Developer ID signature from other Apple-issued ones.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"

	"sentinelgo/internal/osinfo/shared"
)

const (
	secCSDefaultFlags       = 0
	secCSSigningInformation = 1 << 1 // kSecCSSigningInformation
	cfNumberSInt64Type      = 4      // kCFNumberSInt64Type
	cfStringEncodingUTF8    = 0x08000100

	// developerIDRequirement is satisfied only by a Developer ID
	// Application signature: Apple's anchor, the Developer ID intermediate
	// and the Developer ID Application leaf.
	developerIDRequirement = `anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists`
)

var (
	secOnce sync.Once
	secErr  error

	secCodeCopySelf                  func(flags uint32, code *uintptr) int32
	secCodeCopySigningInformation    func(code uintptr, flags uint32, info *uintptr) int32
	secCodeCopyDesignatedRequirement func(code uintptr, flags uint32, req *uintptr) int32
	secRequirementCopyString         func(req uintptr, flags uint32, text *uintptr) int32
	secRequirementCreateWithString   func(text uintptr, flags uint32, req *uintptr) int32
	secCodeCheckValidity             func(code uintptr, flags uint32, req uintptr) int32

	cfDictionaryGetValue              func(dict, key uintptr) uintptr
	cfGetTypeID                       func(obj uintptr) uintptr
	cfStringGetTypeID                 func() uintptr
	cfNumberGetTypeID                 func() uintptr
	cfStringCreateWithCString         func(alloc uintptr, s string, enc uint32) uintptr
	cfStringGetLength                 func(s uintptr) int
	cfStringGetMaximumSizeForEncoding func(n int, enc uint32) int
	cfStringGetCString                func(s uintptr, buf *byte, size int, enc uint32) bool
	cfNumberGetValue                  func(n uintptr, typ int, out *int64) bool
	cfRelease                         func(obj uintptr)

	// CFStringRef keys of the signing information dictionary.
	keyIdentifier, keyTeamID, keyFlags uintptr
)

func loadSecurity() error {
	secOnce.Do(func() {
		sec, err := purego.Dlopen("/System/Library/Frameworks/Security.framework/Security", purego.RTLD_GLOBAL|purego.RTLD_NOW)
		if err != nil {
			secErr = fmt.Errorf("load Security: %w", err)
			return
		}
		cf, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_GLOBAL|purego.RTLD_NOW)
		if err != nil {
			secErr = fmt.Errorf("load CoreFoundation: %w", err)
			return
		}
		purego.RegisterLibFunc(&secCodeCopySelf, sec, "SecCodeCopySelf")
		purego.RegisterLibFunc(&secCodeCopySigningInformation, sec, "SecCodeCopySigningInformation")
		purego.RegisterLibFunc(&secCodeCopyDesignatedRequirement, sec, "SecCodeCopyDesignatedRequirement")
		purego.RegisterLibFunc(&secRequirementCopyString, sec, "SecRequirementCopyString")
		purego.RegisterLibFunc(&secRequirementCreateWithString, sec, "SecRequirementCreateWithString")
		purego.RegisterLibFunc(&secCodeCheckValidity, sec, "SecCodeCheckValidity")
		purego.RegisterLibFunc(&cfDictionaryGetValue, cf, "CFDictionaryGetValue")
		purego.RegisterLibFunc(&cfGetTypeID, cf, "CFGetTypeID")
		purego.RegisterLibFunc(&cfStringGetTypeID, cf, "CFStringGetTypeID")
		purego.RegisterLibFunc(&cfNumberGetTypeID, cf, "CFNumberGetTypeID")
		purego.RegisterLibFunc(&cfStringCreateWithCString, cf, "CFStringCreateWithCString")
		purego.RegisterLibFunc(&cfStringGetLength, cf, "CFStringGetLength")
		purego.RegisterLibFunc(&cfStringGetMaximumSizeForEncoding, cf, "CFStringGetMaximumSizeForEncoding")
		purego.RegisterLibFunc(&cfStringGetCString, cf, "CFStringGetCString")
		purego.RegisterLibFunc(&cfNumberGetValue, cf, "CFNumberGetValue")
		purego.RegisterLibFunc(&cfRelease, cf, "CFRelease")
		for _, k := range []struct {
			dst  *uintptr
			name string
		}{
			{&keyIdentifier, "kSecCodeInfoIdentifier"},
			{&keyTeamID, "kSecCodeInfoTeamIdentifier"},
			{&keyFlags, "kSecCodeInfoFlags"},
		} {
			if *k.dst, err = cfConstant(sec, k.name); err != nil {
				secErr = err
				return
			}
		}
	})
	return secErr
}

// cfConstant reads an exported CFStringRef constant: the symbol is the
// address of the variable that holds the reference.
func cfConstant(lib uintptr, name string) (uintptr, error) {
	sym, err := purego.Dlsym(lib, name)
	if err != nil || sym == 0 {
		return 0, fmt.Errorf("%s: %v", name, err)
	}
	v := **(**uintptr)(unsafe.Pointer(&sym))
	if v == 0 {
		return 0, fmt.Errorf("%s is nil", name)
	}
	return v, nil
}

// cfString copies a CFString into a Go string; ok is false when s isn't one.
func cfString(s uintptr) (string, bool) {
	if s == 0 || cfGetTypeID(s) != cfStringGetTypeID() {
		return "", false
	}
	size := cfStringGetMaximumSizeForEncoding(cfStringGetLength(s), cfStringEncodingUTF8) + 1
	if size <= 1 {
		return "", true
	}
	buf := make([]byte, size)
	if !cfStringGetCString(s, &buf[0], size, cfStringEncodingUTF8) {
		return "", false
	}
	if i := bytes.IndexByte(buf, 0); i >= 0 {
		buf = buf[:i]
	}
	return string(buf), true
}

// cfInt64 reads a CFNumber; ok is false when n isn't one.
func cfInt64(n uintptr) (int64, bool) {
	if n == 0 || cfGetTypeID(n) != cfNumberGetTypeID() {
		return 0, false
	}
	var v int64
	return v, cfNumberGetValue(n, cfNumberSInt64Type, &v)
}

// selfSignature is the running code's signature, read once per process
// (it can't change while the process runs). Nil when it can't be read.
var selfSignature = sync.OnceValue(readSelfSignature)

func readSelfSignature() *shared.AgentCodeSignature {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	if loadSecurity() != nil {
		return nil
	}
	sig, err := querySelf()
	if err != nil {
		return nil
	}
	sig.Path = bundlePath(exe)
	return sig
}

// querySelf asks the Security framework about the running code.
func querySelf() (*shared.AgentCodeSignature, error) {
	var code uintptr
	if st := secCodeCopySelf(secCSDefaultFlags, &code); st != 0 || code == 0 {
		return nil, fmt.Errorf("SecCodeCopySelf: OSStatus %d", st)
	}
	defer cfRelease(code)
	var info uintptr
	if st := secCodeCopySigningInformation(code, secCSSigningInformation, &info); st != 0 || info == 0 {
		return nil, fmt.Errorf("SecCodeCopySigningInformation: OSStatus %d", st)
	}
	defer cfRelease(info)

	sig := &shared.AgentCodeSignature{}
	ident, ok := cfString(cfDictionaryGetValue(info, keyIdentifier))
	facts := sigFacts{signed: ok && ident != ""}
	if !facts.signed {
		sig.Signature = classifySignature(facts)
		return sig, nil
	}
	sig.Identifier = &ident
	if f, ok := cfInt64(cfDictionaryGetValue(info, keyFlags)); ok {
		facts.flags = uint32(f) // #nosec G115 -- SecCodeSignatureFlags is a 32-bit mask
	}
	team, _ := cfString(cfDictionaryGetValue(info, keyTeamID))
	if team != "" && facts.flags&(codeSigFlagAdhoc|codeSigFlagLinkerSigned) == 0 {
		facts.developerID = satisfies(code, developerIDRequirement)
	}
	sig.Signature = classifySignature(facts)
	if sig.Signature == SigDeveloperID {
		sig.TeamID = &team
	}
	if dr, ok := designatedRequirement(code); ok {
		sig.DesignatedRequirement = &dr
	}
	return sig, nil
}

// designatedRequirement returns the code's designated requirement as text.
func designatedRequirement(code uintptr) (string, bool) {
	var req uintptr
	if st := secCodeCopyDesignatedRequirement(code, secCSDefaultFlags, &req); st != 0 || req == 0 {
		return "", false
	}
	defer cfRelease(req)
	var text uintptr
	if st := secRequirementCopyString(req, secCSDefaultFlags, &text); st != 0 || text == 0 {
		return "", false
	}
	defer cfRelease(text)
	s, ok := cfString(text)
	return s, ok && s != ""
}

// satisfies reports whether the running code is valid and meets the
// requirement given as text.
func satisfies(code uintptr, requirement string) bool {
	text := cfStringCreateWithCString(0, requirement, cfStringEncodingUTF8)
	if text == 0 {
		return false
	}
	defer cfRelease(text)
	var req uintptr
	if st := secRequirementCreateWithString(text, secCSDefaultFlags, &req); st != 0 || req == 0 {
		return false
	}
	defer cfRelease(req)
	return secCodeCheckValidity(code, secCSDefaultFlags, req) == 0
}
