package mdm

import "testing"

func TestClassifySignature(t *testing.T) {
	for _, tc := range []struct {
		name  string
		facts sigFacts
		want  string
	}{
		{"unsigned", sigFacts{}, SigUnsigned},
		{"unsigned ignores flags", sigFacts{flags: codeSigFlagAdhoc}, SigUnsigned},
		{"adhoc", sigFacts{signed: true, flags: codeSigFlagAdhoc}, SigAdhoc},
		{"go linker on arm64", sigFacts{signed: true, flags: codeSigFlagAdhoc | codeSigFlagLinkerSigned}, SigAdhoc},
		{"linker-signed only", sigFacts{signed: true, flags: codeSigFlagLinkerSigned}, SigAdhoc},
		{"adhoc wins over developer id", sigFacts{signed: true, flags: codeSigFlagAdhoc, developerID: true}, SigAdhoc},
		{"developer id", sigFacts{signed: true, flags: 0x10000, developerID: true}, SigDeveloperID},
		{"other apple certificate", sigFacts{signed: true}, SigOther},
	} {
		if got := classifySignature(tc.facts); got != tc.want {
			t.Errorf("%s: classifySignature(%+v) = %q, want %q", tc.name, tc.facts, got, tc.want)
		}
	}
}

func TestBundlePath(t *testing.T) {
	for _, tc := range []struct{ exe, want string }{
		{"/opt/sentinelgo/SentinelGo.app/Contents/MacOS/sentinelgo", "/opt/sentinelgo/SentinelGo.app"},
		{"/Applications/My Agent.app/Contents/MacOS/sentinelgo", "/Applications/My Agent.app"},
		{"/opt/sentinelgo/sentinelgo", "/opt/sentinelgo/sentinelgo"},
		{"/opt/x/Contents/MacOS/sentinelgo", "/opt/x/Contents/MacOS/sentinelgo"},           // not a .app
		{"/opt/X.app/Resources/MacOS/sentinelgo", "/opt/X.app/Resources/MacOS/sentinelgo"}, // not Contents
		{"/opt/X.app/Contents/bin/sentinelgo", "/opt/X.app/Contents/bin/sentinelgo"},       // not MacOS
		{"/.app/Contents/MacOS/sentinelgo", "/.app/Contents/MacOS/sentinelgo"},             // no bundle name
	} {
		if got := bundlePath(tc.exe); got != tc.want {
			t.Errorf("bundlePath(%q) = %q, want %q", tc.exe, got, tc.want)
		}
	}
}

func TestFDAState(t *testing.T) {
	yes, no := true, false
	if got := fdaState(&yes); got != FDAGranted {
		t.Errorf("granted: %q", got)
	}
	if got := fdaState(&no); got != FDADenied {
		t.Errorf("denied: %q", got)
	}
	if got := fdaState(nil); got != FDAUnknown {
		t.Errorf("unknown: %q", got)
	}
}
