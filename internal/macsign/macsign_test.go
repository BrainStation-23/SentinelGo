package macsign

import "testing"

func TestHasAuthority(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want bool
	}{
		{
			name: "internal CA signature",
			out: `Executable=/opt/sentinelgo/sentinelgo
Identifier=com.sentinelgo.agent
Format=Mach-O thin (arm64)
CodeDirectory v=20500 size=51234 flags=0x10000(runtime) hashes=1590+2 location=embedded
Signature size=1683
Authority=SentinelGo Code Signing
Authority=SentinelGo Internal Root CA
Signed Time=14 Nov 2026 at 10:00:00
Info.plist=not bound
TeamIdentifier=not set
`,
			want: true,
		},
		{
			name: "Developer ID signature",
			out: `Identifier=com.sentinelgo.agent
Authority=Developer ID Application: Example Ltd (ABCDE12345)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
TeamIdentifier=ABCDE12345
`,
			want: true,
		},
		{
			name: "ad-hoc signature",
			out: `Executable=/opt/sentinelgo/sentinelgo
Identifier=sentinelgo-darwin-arm64
CodeDirectory v=20400 size=50000 flags=0x2(adhoc) hashes=1560+2 location=embedded
Signature=adhoc
TeamIdentifier=not set
`,
			want: false,
		},
		{
			name: "Go linker signature",
			out: `Identifier=a.out
CodeDirectory v=20400 size=50000 flags=0x20002(adhoc,linker-signed) hashes=1560+0 location=embedded
Signature=adhoc
`,
			want: false,
		},
		{
			name: "unsigned",
			out:  "/opt/sentinelgo/sentinelgo: code object is not signed at all\n",
			want: false,
		},
		{name: "no output", out: "", want: false},
		{
			name: "Authority inside another value is not a signer",
			out:  "Executable=/tmp/Authority=x\nSignature=adhoc\n",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasAuthority(tt.out); got != tt.want {
				t.Errorf("hasAuthority() = %v, want %v", got, tt.want)
			}
		})
	}
}
