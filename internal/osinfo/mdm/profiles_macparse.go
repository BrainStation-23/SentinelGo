package mdm

import (
	"regexp"
	"slices"
	"strings"
)

// maxPayloadTypes bounds the reported payload types; a device has a few
// dozen at most.
const maxPayloadTypes = 100

// payloadTypeRE finds each payload's type in the XML plist that
// `profiles -C -o stdout-xml` prints. Profile items are dictionaries with a
// PayloadType key; the outer profiles have none, so every match is a payload.
var payloadTypeRE = regexp.MustCompile(`<key>PayloadType</key>\s*<string>([^<]{1,200})</string>`)

// parsePayloadTypes returns the sorted, de-duplicated payload types of the
// installed configuration profiles.
func parsePayloadTypes(xml string) []string {
	var types []string
	for _, m := range payloadTypeRE.FindAllStringSubmatch(xml, -1) {
		t := strings.TrimSpace(m[1])
		if t != "" && !slices.Contains(types, t) {
			types = append(types, t)
		}
	}
	slices.Sort(types)
	if len(types) > maxPayloadTypes {
		types = types[:maxPayloadTypes]
	}
	return types
}

// settingsByPayload maps a configuration profile payload type to the setting
// it enforces, in the names the console uses for its switches and checks.
var settingsByPayload = map[string]string{
	"com.apple.security.firewall":                "firewall",
	"com.apple.screensaver":                      "screen_lock",
	"com.apple.MCX.FileVault2":                   "filevault",
	"com.apple.security.FDERecoveryKeyEscrow":    "filevault",
	"com.apple.mobiledevice.passwordpolicy":      "password_policy",
	"com.apple.systemuiserver":                   "removable_media",
	"com.apple.applicationaccess":                "restrictions",
	"com.apple.SoftwareUpdate":                   "software_update",
	"com.apple.TCC.configuration-profile-policy": "privacy_permissions",
	"com.apple.notificationsettings":             "notifications",
	"com.apple.system-extension-policy":          "system_extensions",
	"com.apple.loginwindow":                      "login_window",
}

// managedSettings maps payload types to the settings they enforce, sorted
// and de-duplicated. Unknown payload types are only in the raw list.
func managedSettings(payloadTypes []string) []string {
	var out []string
	for _, t := range payloadTypes {
		if s, ok := settingsByPayload[t]; ok && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}
