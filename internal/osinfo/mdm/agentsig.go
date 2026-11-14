package mdm

import (
	"path"
	"strings"
)

// The agent's own code signature and Full Disk Access state (#339). The
// server builds the Full Disk Access grant (a PPPC profile) from what the
// agent reports here, so nobody types in a bundle ID or team ID
// (Compliance-OS#530). The values are read in agentsig_darwin.go; the
// decisions below are platform-neutral so they're tested everywhere.

// Signature kinds reported in AgentCodeSignature.Signature.
const (
	SigDeveloperID = "developer_id"
	SigAdhoc       = "adhoc"
	SigUnsigned    = "unsigned"
	// SigOther is a certificate signature that isn't Developer ID: another
	// Apple-issued certificate (Apple Development, for example) or our
	// internal CA's (#352). designated_requirement identifies it.
	SigOther = "other"
)

// Full Disk Access states reported in MDMAgent.FullDiskAccess.
const (
	FDAGranted = "granted"
	FDADenied  = "denied"
	FDAUnknown = "unknown"
)

// Code signature flags (SecCodeSignatureFlags).
const (
	codeSigFlagAdhoc        = 0x0002  // kSecCodeSignatureAdhoc
	codeSigFlagLinkerSigned = 0x20000 // kSecCodeSignatureLinkerSigned (the Go linker on arm64)
)

// sigFacts are what the Security framework says about the running code.
type sigFacts struct {
	signed      bool   // it has a signature (an identifier)
	flags       uint32 // kSecCodeInfoFlags
	developerID bool   // it satisfies the Developer ID requirement
}

// classifySignature turns the facts into the reported kind.
func classifySignature(f sigFacts) string {
	switch {
	case !f.signed:
		return SigUnsigned
	case f.flags&(codeSigFlagAdhoc|codeSigFlagLinkerSigned) != 0:
		return SigAdhoc
	case f.developerID:
		return SigDeveloperID
	default:
		return SigOther
	}
}

// bundlePath returns the app bundle an executable runs from
// (/x/SentinelGo.app for /x/SentinelGo.app/Contents/MacOS/sentinelgo), or
// the executable itself when it isn't in a bundle. Paths are macOS paths,
// so this uses slash-separated path handling on every OS.
func bundlePath(exe string) string {
	macOS := path.Dir(exe)
	contents := path.Dir(macOS)
	bundle := path.Dir(contents)
	name := path.Base(bundle)
	if path.Base(macOS) == "MacOS" && path.Base(contents) == "Contents" &&
		strings.HasSuffix(name, ".app") && len(name) > len(".app") {
		return bundle
	}
	return exe
}

// fdaState reports the Full Disk Access check (true, false or nil for
// unknown) as the contract's string.
func fdaState(granted *bool) string {
	switch {
	case granted == nil:
		return FDAUnknown
	case *granted:
		return FDAGranted
	default:
		return FDADenied
	}
}
