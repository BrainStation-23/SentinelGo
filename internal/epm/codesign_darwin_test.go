//go:build darwin

package epm

import "testing"

func TestFirstAuthority_FindsFirstEntry(t *testing.T) {
	output := `Executable=/Applications/Foo.app/Contents/MacOS/Foo
Identifier=com.example.foo
Format=app bundle with Mach-O universal (x86_64 arm64)
CodeDirectory v=20500 size=1234 flags=0x10000(runtime) hashes=20+7 location=embedded
Signature size=4681
Authority=Developer ID Application: Example Corp (ABCDE12345)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Info.plist entries=23
TeamIdentifier=ABCDE12345
`
	got, err := firstAuthority(output)
	if err != nil {
		t.Fatalf("firstAuthority: %v", err)
	}
	want := "Developer ID Application: Example Corp (ABCDE12345)"
	if got != want {
		t.Errorf("firstAuthority = %q, want %q", got, want)
	}
}

func TestFirstAuthority_NoAuthorityLine(t *testing.T) {
	output := "code object is not signed at all\n"
	_, err := firstAuthority(output)
	if err == nil {
		t.Fatal("expected error when no Authority= line is present")
	}
}

func TestFirstAuthority_EmptyOutput(t *testing.T) {
	_, err := firstAuthority("")
	if err == nil {
		t.Fatal("expected error for empty codesign output")
	}
}
