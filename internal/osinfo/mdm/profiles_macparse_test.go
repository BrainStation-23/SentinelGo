package mdm

import (
	"slices"
	"strings"
	"testing"
)

const profilesXML = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>_computerlevel</key><array>
  <dict><key>ProfileIdentifier</key><string>com.example.security</string>
    <key>ProfileItems</key><array>
      <dict><key>PayloadType</key>
            <string>com.apple.security.firewall</string></dict>
      <dict><key>PayloadType</key><string>com.apple.MCX.FileVault2</string></dict>
      <dict><key>PayloadType</key><string>com.apple.security.FDERecoveryKeyEscrow</string></dict>
      <dict><key>PayloadType</key><string>com.example.custom</string></dict>
      <dict><key>PayloadType</key><string>com.apple.security.firewall</string></dict>
    </array></dict>
</array></dict></plist>`

func TestParsePayloadTypes(t *testing.T) {
	got := parsePayloadTypes(profilesXML)
	want := []string{"com.apple.MCX.FileVault2", "com.apple.security.FDERecoveryKeyEscrow", "com.apple.security.firewall", "com.example.custom"}
	if !slices.Equal(got, want) {
		t.Errorf("payload types = %v, want %v", got, want)
	}
	if got := parsePayloadTypes(""); got != nil {
		t.Errorf("no profiles: %v", got)
	}
	var many strings.Builder
	for i := range maxPayloadTypes + 20 {
		many.WriteString("<key>PayloadType</key><string>com.example.p" + strings.Repeat("x", i) + "</string>")
	}
	if n := len(parsePayloadTypes(many.String())); n != maxPayloadTypes {
		t.Errorf("payload types not capped: %d", n)
	}
}

func TestManagedSettings(t *testing.T) {
	got := managedSettings(parsePayloadTypes(profilesXML))
	if !slices.Equal(got, []string{"filevault", "firewall"}) {
		t.Errorf("managed settings = %v, want filevault and firewall once each", got)
	}
	if got := managedSettings([]string{"com.example.custom"}); got != nil {
		t.Errorf("unknown payload mapped to %v", got)
	}
}
